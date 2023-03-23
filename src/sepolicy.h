/* sepolicy.h - Header for magiskpolicy non-public APIs
 *
 * Taken from https://github.com/topjohnwu/magiskpolicy/
 */

#ifndef _SEPOLICY_H
#define _SEPOLICY_H

#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <sepol/debug.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/avrule_block.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/constraint.h>

// hashtab traversal macro
#define hashtab_for_each(table, ptr) \
	for (int _i = 0; _i < table->size; ++_i) \
		for (*ptr = table->htable[_i]; *ptr != NULL; *ptr = (*ptr)->next)

// Global policydb
extern policydb_t *policydb;

// sepolicy manipulation functions
int create_domain(char *d);
int set_domain_state(char* s, int state);
int add_transition(char *s, char *t, char *c, char *d);
int add_file_transition(char *s, char *t, char *c, char *d, char* filename);
int add_typeattribute(char *domainS, char *attr);
int add_rule(char *s, char *t, char *c, char *p, int effect, int not);
int add_xperm_rule(char *s, char *t, char *c, char *range, int effect, int not);

extern int policydb_index_decls(sepol_handle_t * handle, policydb_t * p);


// policydb functions
int load_policydb(const char *filename);
int dump_policydb(const char *filename);
void destroy_policydb();

// Handy functions
int sepol_allow(char *s, char *t, char *c, char *p);
int sepol_deny(char *s, char *t, char *c, char *p);
int sepol_auditallow(char *s, char *t, char *c, char *p);
int sepol_auditdeny(char *s, char *t, char *c, char *p);
int sepol_typetrans(char *s, char *t, char *c, char *d, char *o);
int sepol_allowxperm(char *s, char *t, char *c, char *range);
int sepol_auditallowxperm(char *s, char *t, char *c, char *range);
int sepol_dontauditxperm(char *s, char *t, char *c, char *range);
int sepol_create(char *s);
int sepol_permissive(char *s);
int sepol_enforce(char *s);
int sepol_attradd(char *s, char *a);
int sepol_exists(char *source);

#endif
