// a multiplexor that reads lines from stdin and round-robin them to a pool of processes
// (the intent is to read as fast as possible so that the process at the other end of
// the pipe doesn't block
//
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

// 65535 - 8 byte UDP header - 20 byte IP header
#define LINE_BUF_SZ 65507
#define CMD_BUF_SZ 1024

char buf[ LINE_BUF_SZ ], cmd_buf[ CMD_BUF_SZ ];


// commandline arguments
struct args {
	int n_proc, n_lines;    // no. child processes, no. lines to read (0 = infinite)
	char const *cmd;
} args;

void parse_args(  int const argc, char *const *const argv ) {
	if ( 1 == argc ) {    // no arguments, use defaults
		return;
	}

	int k;
	char const *arg;
	for ( int i = 1; i < argc; ++i ) {
		arg = argv[ i ];
		if ( !strcmp( "-proc", arg ) ) {
			++i;
			if ( argc == i ) {
				fprintf( stderr, "Missing argument after -proc\n" );
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
			++i;
			if ( argc == i ) {
				fprintf( stderr, "Missing argument after -lines\n" );
				exit( 1 );
			}
			k = atoi( argv[ i ] );
			if ( k < 0 ) {
				fprintf( stderr, "-lines argument too small: %d\n", k );
				exit( 1 );
			}
			args.n_lines = k;
		} else if ( !strcmp( "-cmd", arg ) ) {
			++i;
			if ( argc == i ) {
				fprintf( stderr, "Missing argument after -cmd\n" );
				exit( 1 );
			}
			arg = argv[ i ];
			k = strlen( arg );
			if ( 0 == k ) {
				fprintf( stderr, "-cmd argument empty\n" );
				exit( 1 );
			}
			if ( k > CMD_BUF_SZ - 20 ) {
				fprintf( stderr, "-cmd argument too long: %d\n", k );
				exit( 1 );
			}
			args.cmd = arg;
		} else {
			fprintf( stderr, "Unknown argument: %s\n", arg );
			exit( 1 );
		}
	}  // while

	// cmd is a required argument
	if ( NULL == args.cmd ) {
		fprintf( stderr, "Missing -cmd option\n" );
		exit( 1 );
	}
	printf( "n_proc = %d, n_lines = %d\ncmd = %s\n",
                args.n_proc, args.n_lines, args.cmd );
}  // parse_args

int main( int argc, char **argv ) {    // needs no arguments
	// defaults
	args.n_proc = 2;
	args.n_lines = 0;  // infinite
	args.cmd = NULL;

	parse_args( argc, argv );

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
		sprintf( cmd_buf, "%s >> out_%d.log", args.cmd, i );
		printf( "cmd = %s\n", cmd_buf );
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
	printf( "Created %d children\n", args.n_proc );

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
