#include "common.h"




void canonize_number(const str uri, number_t canon_number)
{
	char *s = uri.s;
	int pos = 0;
	int cpos = 0;
	int nstart = 0;
	char * prefix = "sip:";

  canon_number[0] = 0;
  if (s==NULL) return;

	while (nstart<4) {
		if (pos >= uri.len) break;
		if (s[pos]==prefix[nstart]) nstart++;
		else nstart=0;
		pos++;
	}
	while (pos < uri.len && (s[pos] < '0' || s[pos] > '9')) pos++;

	if (pos + 1 < uri.len && s[pos]=='0' && s[pos+1]=='0') pos+=2;
  if (pos < uri.len && s[pos]=='0') {
		pos++;
		canon_number[0] = '4';
		canon_number[1] = '9';
		cpos = 2;
	}

	while (pos < uri.len && cpos < MAXNUMBERLEN && s[pos] >= '0' && s[pos] <= '9') {
		canon_number[cpos++] = s[pos++];
	}

	canon_number[cpos] = 0;
}
