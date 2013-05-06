// a multiplexor that reads lines from stdin and round-robin them to a pool of processes
// (the intent is to read as fast as possible so that the process at the other end of
// the pipe doesn't block)
//
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

// 65535 - 8 byte UDP header - 20 byte IP header
#define LINE_BUF_SZ 65507
#define CMD_BUF_SZ 1024

char buf[ LINE_BUF_SZ ], cmd_buf[ CMD_BUF_SZ ];

// defaults
char const *const DEF_OUTPUT_FILE = "/var/tmp/multiplexor_";
int const DEF_PROC = 2;
int const DEF_LINES = 0;

// commandline arguments
struct args {
	int  n_proc;            // no. of child processes
	long n_lines;           // no. of lines to read (0 = infinite)
	char const
		*o_path,     // path to output file name
		*p_path,     // path to pipe command name
		*cmd;        // path to subprocess command name
} args;

// bit flags to record which options were seen
enum { N_PROC      = 1,
       N_LINES     = (N_PROC << 1),
       COMMAND     = (N_LINES << 1),
       OUTPUT_FILE = (COMMAND << 1),
       OUTPUT_PIPE = (OUTPUT_FILE << 1)
};

void usage() {
	fprintf( stderr, "Options:\n"
		 "-cmd <cmd>   -- command to run in subprocesses (default: none)\n"
		 "[-proc n]    -- number of child processes to create (default: %d)\n"
		 "[-lines n]   -- max. lines to process (default: 0 = infinite)\n"
		 "[-o <path>]  -- path to output files (default: %s)\n"
		 "[-p <cmd>]   -- path to output pipe command (default: none)\n"
		 "Only one of -o and -p is allowed; -cmd is required\n",
		 DEF_PROC, DEF_OUTPUT_FILE );
}  // usage

// write address of malloc'ed copy of s to *d; the copy has whitespace at both ends removed.
// function returns size of new string; if this is zero, no malloc is done and *d is not
// modified
//
int trim( char const *const s, int const s_len, char const **d ) {
	if ( ! s_len )       // s is empty
		return 0;

	char const *p = s, *s_start = NULL;

	for ( ; ; ++p ) {    // find first non-blank char
		int const c = (0xff & *p);    // mask off any sign extension
		if ( ! c )
			break;                // end of string
		if ( isspace( c ) )           // skip white space
			continue;
		s_start = p++;                // found beginning
		break;
	}
	if ( NULL == s_start )                // s is blank
		return 0;

	// s is not blank
	p = s + s_len - 1;                    // pointer to last char of s
	for ( ; ; --p ) {                     // find last non-blank char
		int const c = *p & 0xff;      // mask off any sign extension
		if ( ! c ) {                  // null byte, should never happen
			fprintf( stderr, "Unexpected null byte" );
			exit( 1 );
		}
		if ( ! isspace( c ) )         // found end
			break;
	}

	int const len     = p - s_start + 1,            // length of new string
	          n_bytes = len + 1;                    // null byte
	char *const dest = (char *)malloc( n_bytes );
	if ( NULL == dest ) {
		fprintf( stderr, "malloc(%d) failed\n", n_bytes );
		exit( 1 );
	}
	memcpy( dest, s_start, len );
	dest[ len ] = 0;    // terminating null byte
	*d = dest;
	return len;
}  // trim

void parse_args(  int const argc, char *const *const argv ) {
	if ( 1 == argc ) {    // no arguments, use defaults
		return;
	}

	long n;
	int k, len, arg_flags = 0;
	char const *arg, *path;
	for ( int i = 1; i < argc; ++i ) {
		arg = argv[ i ];
		if ( !strcmp( "-proc", arg ) ) {
			if ( N_PROC & arg_flags ) {
				fprintf( stderr, "Duplicate -proc option\n" );
				exit( 1 );
			} 
			arg_flags |= N_PROC;
			++i;
			if ( argc == i ) {
				fprintf( stderr, "Missing argument after -proc\n" ); usage();
				exit( 1 );
			}
			k = atoi( argv[ i ] );
			if ( k < 1 ) {
				fprintf( stderr, "-proc argument too small: %d\n", k );
				exit( 1 );
			}
			if ( k > 1000 ) {
				fprintf( stderr, "-proc argument too large: %d\n", k );
				exit( 1 );
			}
			args.n_proc = k;
		} else if ( !strcmp( "-lines", arg ) ) {
			if ( N_LINES & arg_flags ) {
				fprintf( stderr, "Duplicate -lines option\n" );
				exit( 1 );
			} 
			arg_flags |= N_LINES;
			++i;
			if ( argc == i ) {
				fprintf( stderr, "Missing argument after -lines\n" );
				exit( 1 );
			}
			n = atol( argv[ i ] );
			if ( n < 0 ) {
				fprintf( stderr, "-lines argument too small: %ld\n", n );
				exit( 1 );
			}
			args.n_lines = n;
		} else if ( !strcmp( "-cmd", arg ) ) {
			if ( COMMAND & arg_flags ) {
				fprintf( stderr, "Duplicate -cmd option\n" );
				exit( 1 );
			} 
			arg_flags |= COMMAND;
			++i;
			if ( argc == i ) {
				fprintf( stderr, "Missing argument after -cmd\n" );
				exit( 1 );
			}
			path = argv[ i ];
			k = strlen( path );
			if ( ! k ) {
				fprintf( stderr, "-cmd argument empty\n" );
				exit( 1 );
			}
			len = trim( path, k, &args.cmd );
			if ( ! len ) {
				fprintf( stderr, "-cmd argument blank\n" );
				exit( 1 );
			}
		} else if ( !strcmp( "-o", arg ) ) {
			if ( OUTPUT_FILE & arg_flags ) {
				fprintf( stderr, "Duplicate -o option\n" );
				exit( 1 );
			} 
			if ( OUTPUT_PIPE & arg_flags ) {
				fprintf( stderr, "Cannot use both -p and -o options\n" );
				exit( 1 );
			} 
			arg_flags |= OUTPUT_FILE;
			++i;
			if ( argc == i ) {
				fprintf( stderr, "Missing argument after -o\n" ); usage();
				exit( 1 );
			}
			path = argv[ i ];
			k = strlen( path );
			if ( ! k ) {
				fprintf( stderr, "-o argument empty\n" );
				exit( 1 );
			}
			len = trim( path, k, &args.o_path );
			if ( ! len ) {
				fprintf( stderr, "-o argument blank\n" );
				exit( 1 );
			}
		} else if ( !strcmp( "-p", arg ) ) {
			if ( OUTPUT_PIPE & arg_flags ) {
				fprintf( stderr, "Duplicate -p option\n" );
				exit( 1 );
			} 
			if ( OUTPUT_FILE & arg_flags ) {
				fprintf( stderr, "Cannot use both -o and -p options\n" );
				exit( 1 );
			} 
			arg_flags |= OUTPUT_PIPE;
			++i;
			if ( argc == i ) {
				fprintf( stderr, "Missing argument after -p\n" ); usage();
				exit( 1 );
			}
			path = argv[ i ];
			k = strlen( path );
			if ( ! k ) {
				fprintf( stderr, "-p argument empty\n" );
				exit( 1 );
			}
			len = trim( path, k, &args.p_path );
			if ( ! len ) {
				fprintf( stderr, "-p argument blank\n" );
				exit( 1 );
			}
		} else {
			fprintf( stderr, "Unknown argument: %s\n", arg ); usage();
			exit( 1 );
		}
	}  // while

	// cmd is a required argument
	if ( NULL == args.cmd ) {
		fprintf( stderr, "Missing -cmd option\n" );
		exit( 1 );
	}
	printf( "n_proc = %d, n_lines = %ld\ncommand = %s\no_path = %s\np_path = %s\n",
		args.n_proc, args.n_lines, args.cmd, args.o_path, args.p_path );
}  // parse_args

int main( int argc, char **argv ) {
	// defaults
	args.n_proc = DEF_PROC;
	args.n_lines = DEF_LINES;  // infinite
	args.cmd = NULL;

	parse_args( argc, argv );

	// set default output file name if necessary
	if ( !(args.o_path || args.p_path) ) {
		args.o_path = DEF_OUTPUT_FILE;
	}

	// allocate space for output file pointers
	int const nbytes = args.n_proc * sizeof( FILE * );
	FILE **const ofiles = (FILE **)malloc( nbytes );
	if ( NULL == ofiles ) {
		fprintf( stderr, "malloc( %d ) failed\n", nbytes );
		exit( 1 );
	}

	// create child processes
	FILE **optr = ofiles;
	FILE *const *const optr_end = optr + args.n_proc;
	for ( int i = 0; optr < optr_end; ++i, ++optr ) {
		// create child process
		if ( args.o_path ) {    // file path
			sprintf( cmd_buf, "%s >> %s_%d.txt", args.cmd, args.o_path, i );
		} else {                // pipe command path
			sprintf( cmd_buf, "%s | %s", args.cmd, args.p_path );
		}
		//printf( "cmd = %s\n", cmd_buf );

                errno = 0;     // popen() does not set this for some errors
		*optr = popen( cmd_buf, "w" );
		if ( NULL == *optr ) {
			fprintf( stderr, "popen( %s ) failed, i = %d\n", cmd_buf, i );
                        if ( errno ) {
				perror( "popen() failed\n" );
			}
			exit( 1 );
		}
	}
	//printf( "Created %d children\n", args.n_proc );

	// multiplex data
	optr = ofiles;
	if ( 0 == args.n_lines ) {    // no line limit
		while ( NULL != fgets( buf, LINE_BUF_SZ, stdin ) ) {
			if ( EOF == fputs( buf, *optr ) )
				break;
                        optr++;
			if ( optr_end == optr ) {
				optr = ofiles;
			}
		}
	} else {                     // quit after reading given number of lines
		for ( int i = 0; i < args.n_lines && NULL != fgets( buf, LINE_BUF_SZ, stdin ); ++i ) {
			if ( EOF == fputs( buf, *optr ) )
				break;
                        optr++;
			if ( optr_end == optr ) {
				optr = ofiles;
			}
		}
	}

	// close all output pipes
	for ( optr = ofiles; optr < optr_end; ++optr ) {
		if ( -1 == pclose( *optr ) ) {
			perror( "pclose() failed\n" );
			exit( 1 );
		}
	}
    return 0;
}  // main
