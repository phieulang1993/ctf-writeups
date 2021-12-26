/*
==================================================================================
||  Author: phieulang1993                                                       ||
||  This challenge is built on cgic library (https://github.com/boutell/cgic)	||
==================================================================================
*/

#include <stdio.h>
#include "cgic.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t b64_decoded_size(const char *in)
{
	size_t len;
	size_t ret;
	size_t i;

	if (in == NULL)
		return 0;

	len = strlen(in);
	ret = len / 4 * 3;

	for (i = len; i-- > 0;)
	{
		if (in[i] == '=')
		{
			ret--;
		}
		else
		{
			break;
		}
	}

	return ret;
}

int b64invs[] = {62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
				 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
				 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
				 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
				 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
				 43, 44, 45, 46, 47, 48, 49, 50, 51};

void b64_generate_decode_table()
{
	int inv[80];
	size_t i;

	memset(inv, -1, sizeof(inv));
	for (i = 0; i < sizeof(b64chars) - 1; i++)
	{
		inv[b64chars[i] - 43] = i;
	}
}
int b64_isvalidchar(char c)
{
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'Z')
		return 1;
	if (c >= 'a' && c <= 'z')
		return 1;
	if (c == '+' || c == '/' || c == '=')
		return 1;
	return 0;
}

char *b64_decode(const char *in)
{
	size_t len;
	size_t i;
	size_t j;
	int v;

	if (in == NULL)
		return NULL;

	len = strlen(in);
	if (len % 4 != 0)
		return NULL;

	char *out = malloc(b64_decoded_size(in));

	for (i = 0; i < len; i++)
	{
		if (!b64_isvalidchar(in[i]))
		{
			return NULL;
		}
	}

	for (i = 0, j = 0; i < len; i += 4, j += 3)
	{
		v = b64invs[in[i] - 43];
		v = (v << 6) | b64invs[in[i + 1] - 43];
		v = in[i + 2] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 2] - 43];
		v = in[i + 3] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 3] - 43];

		out[j] = (v >> 16) & 0xFF;
		if (in[i + 2] != '=')
			out[j + 1] = (v >> 8) & 0xFF;
		if (in[i + 3] != '=')
			out[j + 2] = v & 0xFF;
	}

	return out;
}

int error()
{
	int msg;
	cgiFormInteger("msg", &msg, 0);
	fprintf(cgiOut, "<HTML>\n<HEAD>\n");
	fprintf(cgiOut, "<TITLE>ERROR</TITLE>\n</HEAD>\n");
	fprintf(cgiOut, "<BODY>\n");
	switch (msg)
	{
	case 2000:
		fprintf(cgiOut, "<p>Access Denied</p>\n");
		break;
	case 3000:
		fprintf(cgiOut, "<p>Missing Data</p>\n");
		break;
	case 4000:
		fprintf(cgiOut, "<p>Invalid Data Value</p>\n");
		break;
	case 5000:
		fprintf(cgiOut, "<p>Incorrect Data Type</p>\n");
		break;
	case 6000:
		fprintf(cgiOut, "<p>Unpermitted Character Found!</p>\n");
		break;
	default:
		fprintf(cgiOut, "<p>Error! Please try again!</p>\n");
		break;
	}
	fprintf(cgiOut, "<a href=/index.html>Home</p>\n");
	fprintf(cgiOut, "</BODY>\n</HTML>");
	return 0;
}
void Unauth()
{
	fprintf(cgiOut, "WWW-Authenticate: Basic realm=\"\"\r\n");
	cgiHeaderStatus(401, "Unauthorized");
}

int checkCred(char *user, char *pass)
{
	char buf[101];
	char username[128];
	char password[128];
	FILE *fd = fopen("/var/credential", "r");
	if (fd == NULL)
		return -1;
	fgets(buf, 100, fd);
	if (sscanf(buf, "username=%s\n", username) == EOF)
	{
		fclose(fd);
		return -1;
	}
	fgets(buf, 100, fd);

	if (sscanf(buf, "password=%s", password) == EOF)
	{
		fclose(fd);
		return -1;
	}
	if (!strncmp(username, user, strlen(user)) && !strncmp(password, pass, strlen(pass))) // bypasss authen vuln, strncmp with num = input length
	{
		return 1;
	}
	else
	{
		return -1;
	}
	fclose(fd);
	return 0;
}
int checkAuth()
{
	char username[128];
	char password[128];
	char *deter;
	char *authorization = getenv("HTTP_AUTHORIZATION");
	if (authorization == NULL)
	{
		Unauth();
		return -1;
	}
	else
	{
		char *out = b64_decode(authorization + 6);
		if (out == NULL)
		{
			Unauth();
			return -1;
		}
		deter = strchr(out, ':');
		if (deter == NULL)
		{
			Unauth();
			return -1;
		}
		memset(username, 0, sizeof(username));
		memset(password, 0, sizeof(password));
		strncpy(username, out, (int)(deter - out));			// Stack Overflow Vuln, strncmp with num = input length
		strncpy(password, deter + 1, strlen(deter + 1));	// Stack Overflow Vuln, strncmp with num = input length
		if (strlen(username) == 0 || strlen(password) == 0)
		{
			Unauth();
			return -1;
		}
		if (checkCred(username, password) == -1)
		{
			Unauth();
			return -1;
		}
	}
	return 1;
}
int checkUnpermittedChars(char *s)
{
	char *unpermittedChars = "$&;|`\\><\"'`/\n";
	int idx = 0;
	int len = strlen(s);
	char c;
	do
	{
		c = s[idx];
		if (idx++ == len)
		{
			break;
		}
		if (strchr(unpermittedChars, c) != NULL)
		{
			return 1;
		}
	} while (c);
	return 0;
}

void print_file(char *filename)
{
	FILE *fp = fopen(filename, "rb");
	if (fp == NULL)
	{
		cgiHeaderStatus(404, "Not Found");
		fprintf(cgiOut, "<HTML>\n<HEAD>\n");
		fprintf(cgiOut, "<TITLE>File Not Found</TITLE>\n</HEAD>\n");
		fprintf(cgiOut, "<BODY>\n");
		fprintf(cgiOut, "<p>File Not Found</p>");
		fprintf(cgiOut, "<BODY>");
		return;
	}
	cgiHeaderContentType("text/html");
	char line[2048];
	while (fgets(line, 2048, fp) != NULL)
	{
		fprintf(cgiOut, "%s", line);
	}
	return;
}

void ping()
{
	char ip[256];
	char t[10];
	int c;
	struct in_addr addr;
	if (cgiFormStringNoNewlines("ip", ip, sizeof(ip)) == cgiFormNotFound || cgiFormStringNoNewlines("t", t, sizeof(t)) == cgiFormNotFound)
	{
		cgiHeaderLocation("/cgi-bin/error.cgi?msg=3000"); // MISSING DATA
		return;
	}
	if (cgiFormInteger("c", &c, 0) == cgiFormNotFound)
	{
		c = 1;
	}
	else if(c > 10)
	{
		cgiHeaderLocation("/cgi-bin/error.cgi?msg=4000"); // Invalid Data Value
		return;
	}
	if (!inet_aton(ip, &addr))
	{
		cgiHeaderLocation("/cgi-bin/error.cgi?msg=5000"); // Incorrect Data Type
		return;
	}
	if (checkUnpermittedChars(ip) || checkUnpermittedChars(t))
	{
		cgiHeaderLocation("/cgi-bin/error.cgi?msg=6000"); // Unpermitted Charaacter Found
		return;
	}
	char command[0x200];
	char dirpath[20];
	char fileresult[40];
	snprintf(dirpath, 40, "/tmp/%s", t);
	snprintf(fileresult, 40, "/tmp/%s/ping_result", t);
	snprintf(command, 0x200, "mkdir %s", dirpath);						// Race condition, create .html directory
	system(command);
	snprintf(command, 0x200, "ping -c %d %s > %s", c, ip, fileresult);	// Race condition, create .html directory
	system(command);
	print_file(fileresult);
	snprintf(command, 0x200, "rm -r %s", dirpath);						// Race condition, create .html directory
	system(command);

	return;
}

void load()
{
	char page[256];
	char path[512];
	if (cgiFormString("page", page, sizeof(page)) == cgiFormNotFound)
	{
		cgiHeaderLocation("/cgi-bin/main.cgi?page=admin.html");
		return;
	}
	if (!strstr(page, ".html"))
	{
		cgiHeaderLocation("/cgi-bin/error.cgi?msg=2000");
		return;
	}
	fprintf(cgiOut, page); // Format string, unintended solution, I forgot to remove these debug lines
	memset(path, 0, 512);
	snprintf(path, 512, "/var/www/data/%s", page);	// Path traversal, read arbitrary file with .html directory in path
	fprintf(cgiOut, path); // Format string, unintended solution, I forgot to remove these debug lines
	print_file(path);
}
void ALARMhandler()
{
	cgiHeaderStatus(408, "Request Timeout");
	fprintf(cgiOut, "<p><b>Request Timeout</b></p>");
	exit(1);
}

int cgiMain(int argc, char **argv)
{
	signal(SIGALRM, ALARMhandler);
	alarm(30);

	if (strstr(argv[0], "error.cgi"))
	{
		error();
	}
	else if (checkAuth() == 1)
	{
		if (strstr(argv[0], "main.cgi"))
		{
			load();
		}
		else if (strstr(argv[0], "ping.cgi"))
		{
			ping();
		}
	}

	return 0;
}
