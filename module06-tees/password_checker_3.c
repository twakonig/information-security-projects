#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define CONST_LEN 15

int check_password(char *p, int p_size, char *i, int i_size)
{
	int no_match = 0;

	int pos = 0;
	char r;
	char g;
	int out = 1;

	// compare letters
	for (pos = 0; pos < CONST_LEN; pos++)
	{
		// r for real, g for guessed
		r = p[pos];
		g = i[pos];
		// printf("%d, %d, %c, %c, %d", no_match, pos, r, g, out);
		// RDI, RSI, RDX, RCX, R8, R9
		//    no_match: rbp-0x8
		//    pos: rbp-0x4
		//    r: rbp-0xd
		//    g: rbp-0xe
		//    out: rbp-0xc

		// use the ATNT syntax
		asm(
			"mov -0xd(%rbp), %al \n\t \
			mov -0xe(%rbp), %bl \n\t \
			mov -0xc(%rbp), %cx \n\t \
			mov -0x8(%rbp), %dx \n\t \
			cmp %al, %bl \n\t \
			cmovne %dx, %cx \n\t \
			mov %cx, -0xc(%rbp) \n\t \
			xor %al, %al \n\t \
			xor %bl, %bl \n\t \
			xor %cx, %cx \n\t \
			xor %dx, %dx \n\t");

		// printf("out: %d\n", out);

		/* 		if (r == g)
				{
					// do nothing
				}
				else
				{
					out = 0;
				} */
	}

	return out;
}

// assumptions: password only has small characters [a, z], maximum length is 15 characters
int main(int argc, char *argv[])
{

	if (argc != 3)
	{
		fprintf(stderr, "Usage: %s <password guess> <output_file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	FILE *password_file;
	char password[16] = "\0";

	size_t len = 0;
	char *line;
	password_file = fopen("/home/isl/t2_3/password.txt", "r");

	if (password_file == NULL)
	{
		perror("cannot open password file\n");
		exit(EXIT_FAILURE);
	}

	// set password to e.g.: $$$$$magicbeans
	fgets(password, 16, password_file);
	// printf("pw: %s\n", password);

	// ---------------- intialize array for guess (must always be SAME LENGTH!!) ----------------
	char guessed_pw[16] = "\0";
	int len_guess = strlen(argv[1]);
	int pad_guess = CONST_LEN - len_guess;

	// pad guessed_pw with leading '$'
	for (int p = 0; p < pad_guess; p++)
	{
		guessed_pw[p] = '$';
	}
	// append input (guess)
	for (int i = pad_guess; i < 16; i++)
	{
		guessed_pw[i] = argv[1][i - pad_guess];
	}
	// printf("in: %s\n", guessed_pw);

	//-------------------------------------------------------------------------------------------

	FILE *output_file;
	output_file = fopen(argv[2], "wb");

	int is_match = 0;
	is_match = check_password(password, strlen(password), guessed_pw, strlen(guessed_pw));
	// testing
	// printf("%d\n", is_match);
	fputc(is_match, output_file);
	// fprintf(output_file, "%d", is_match);
	fclose(output_file);

	fclose(password_file);
	return 0;
}

