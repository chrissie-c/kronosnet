/*
 * Copyright (C) 2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */


/*
 * NOTE: this code is very rough, it does the bare minimum to parse the
 * XML out from doxygen and is probably very fragile to changes in that XML
 * schema. It probably leaks memory all over the place too.
 *
 * In its favour, it *does* generate man pages and should only be run very ocasionally
 */

#define _XOPEN_SOURCE
#define _BSD_SOURCE
#define _XOPEN_SOURCE_EXTENDED
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <libxml/tree.h>
#include <qb/qbmap.h>

#define XML_DIR "../../libknet/man/xml"

static int print_ascii = 1;
static int print_man = 0;
static int print_params = 0;
static int num_functions = 0;
static char *man_section="3";
static char *package_name="Kronosnet";
static char *header="Kronosnet Programmer's Manual";
static char *output_dir="./";
static char *xml_dir = XML_DIR;
static char *xml_file = "/libknet_8h.xml";
static qb_map_t *params_map;
static qb_map_t *retval_map;
static qb_map_t *function_map;
static qb_map_t *structures_map;
static qb_map_t *used_structures_map;

struct param_info {
	char *paramname;
	char *paramtype;
	char *paramdesc;
	struct param_info *next;
};

struct struct_info {
	char *structname;
	qb_map_t *params_map;
};

static char *get_texttree(int *type, xmlNode *cur_node, char **returntext);
static void traverse_node(xmlNode *parentnode, char *leafname, void (do_members(xmlNode*, void*)), void *arg);

static void free_paraminfo(struct param_info *pi)
{
	free(pi->paramname);
	free(pi->paramtype);
	free(pi->paramdesc);
	free(pi);
}

static char *get_attr(xmlNode *node, const char *tag)
{
	xmlAttr *this_attr;

	for (this_attr = node->properties; this_attr; this_attr = this_attr->next) {
		if (this_attr->type == XML_ATTRIBUTE_NODE && strcmp((char *)this_attr->name, tag) == 0) {
			return strdup((char *)this_attr->children->content);
		}
	}
	return NULL;
}

static char *get_child(xmlNode *node, const char *tag)
{
	xmlNode *this_node;
	xmlNode *child;
	char buffer[1024] = {'\0'};
	char *refid;
	char *declname = NULL;

	for (this_node = node->children; this_node; this_node = this_node->next) {
		if ((strcmp( (char*)this_node->name, "declname") == 0)) {
			declname = strdup((char*)this_node->children->content);
		}

		if ((this_node->type == XML_ELEMENT_NODE && this_node->children) && ((strcmp((char *)this_node->name, tag) == 0))) {
			refid = NULL;
			for (child = this_node->children; child; child = child->next) {
				if (child->content) {
					strcat(buffer, (char *)child->content);
				}

				if ((strcmp( (char*)child->name, "ref") == 0)) {
					if (child->children->content) {
						strcat(buffer,(char *)child->children->content);
					}
					refid = get_attr(child, "refid");
				}
			}
		}
		if (declname && refid) {
			qb_map_put(used_structures_map, refid, declname);
		}
	}
	return strdup(buffer);
}

int not_all_whitespace(char *string)
{
	int i;

	for (i=0; i<strlen(string); i++) {
		if (string[i] != ' ' &&
		    string[i] != '\n' &&
		    string[i] != '\r' &&
		    string[i] != '\t')
			return 1;
	}
	return 0;
}

void get_param_info(xmlNode *cur_node, qb_map_t *map)
{
	xmlNode *this_tag;
	xmlNode *sub_tag;
	char *paramname = NULL;
	char *paramdesc = NULL;
	struct param_info *pi;

	/* This is not robust, and very inflexible */
	for (this_tag = cur_node->children; this_tag; this_tag = this_tag->next) {
		for (sub_tag = this_tag->children; sub_tag; sub_tag = sub_tag->next) {
			if (sub_tag->type == XML_ELEMENT_NODE && strcmp((char *)sub_tag->name, "parameternamelist") == 0) {
				paramname = (char*)sub_tag->children->next->children->content;
			}
			if (sub_tag->type == XML_ELEMENT_NODE && strcmp((char *)sub_tag->name, "parameterdescription") == 0) {
				paramdesc = (char*)sub_tag->children->next->children->content;

				/* Add text to the param_map */
				pi = qb_map_get(map, paramname);
				if (pi) {
					pi->paramdesc = paramdesc;
				}
				else {
					pi = malloc(sizeof(struct param_info));
					if (pi) {
						pi->paramname = paramname;
						pi->paramdesc = paramdesc;
						pi->paramtype = NULL; /* probably retval */
						qb_map_put(map, paramname, pi);
					}
				}
			}
		}
	}
}

char *get_text(xmlNode *cur_node, char **returntext)
{
	xmlNode *this_tag;
	xmlNode *sub_tag;
	char *kind;
	char buffer[4096] = {'\0'};

	for (this_tag = cur_node->children; this_tag; this_tag = this_tag->next) {
		if (this_tag->type == XML_TEXT_NODE && strcmp((char *)this_tag->name, "text") == 0) {
			if (not_all_whitespace((char*)this_tag->content)) {
				strcat(buffer, (char*)this_tag->content);
				strcat(buffer, "\n");
			}
		}
		if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "emphasis") == 0) {
			if (print_man) {
				strcat(buffer, "\\fB");
			}
			strcat(buffer, (char*)this_tag->children->content);
			if (print_man) {
				strcat(buffer, "\\fR");
			}
		}
		if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "itemizedlist") == 0) {
			for (sub_tag = this_tag->children; sub_tag; sub_tag = sub_tag->next) {
				if (sub_tag->type == XML_ELEMENT_NODE && strcmp((char *)sub_tag->name, "listitem") == 0) {
					strcat(buffer, (char*)sub_tag->children->children->content);
					strcat(buffer, "\n");
				}
			}
		}

		/* Look for subsections - return value & params */
		if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "simplesect") == 0) {
			char *tmp;

			kind = get_attr(this_tag, "kind");
			tmp = get_text(this_tag->children, NULL);

			if (returntext && strcmp(kind, "return") == 0) {
				*returntext = tmp;
			}
		}

		if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "parameterlist") == 0) {
			kind = get_attr(this_tag, "kind");
			if (strcmp(kind, "param") == 0) {
				get_param_info(this_tag, params_map);
			}
			if (strcmp(kind, "retval") == 0) {
				get_param_info(this_tag, retval_map);
			}
		}
	}
	return strdup(buffer);
}

/* Called from traverse_node() */
static void read_struct(xmlNode *cur_node, void *arg)
{
	xmlNode *this_tag;
	struct struct_info *si=arg;
	struct param_info *pi;
	char fullname[1024];
	char *type;
	char *name;
	char *args="";

	for (this_tag = cur_node->children; this_tag; this_tag = this_tag->next) {
		if (strcmp((char*)this_tag->name, "type") == 0) {
			type = (char*)this_tag->children->content ;
		}
		if (strcmp((char*)this_tag->name, "name") == 0) {
			name = (char*)this_tag->children->content ;
		}
		if (this_tag->children && strcmp((char*)this_tag->name, "argsstring") == 0) {
			args = (char*)this_tag->children->content;
		}
	}

	pi = malloc(sizeof(struct param_info));
	if (pi) {
		snprintf(fullname, sizeof(fullname), "%s%s", name, args);
		pi->paramtype = strdup(type);
		pi->paramname = strdup(fullname);
		pi->paramdesc = NULL;
		qb_map_put(si->params_map, name, pi);
	}
}

static int read_structure_from_xml(char *refid, char *name)
{
	char fname[PATH_MAX];
	xmlNode *rootdoc;
	xmlDocPtr doc;
	struct struct_info *si;
	int ret = -1;

	snprintf(fname, sizeof(fname), XML_DIR "/%s.xml", refid);

	doc = xmlParseFile(fname);
	if (doc == NULL) {
		fprintf(stderr, "Error: unable to open xml file for %s\n", refid);
		return -1;
	}

	rootdoc = xmlDocGetRootElement(doc);
	if (!rootdoc) {
		fprintf(stderr, "Can't find \"document root\"\n");
		return -1;
	}

	si = malloc(sizeof(struct struct_info));
	if (si) {
		si->params_map = qb_hashtable_create(10);
		si->structname = strdup(name);
		traverse_node(rootdoc, "memberdef", read_struct, si);
		ret = 0;
		qb_map_put(structures_map, refid, si);
	}
	xmlFreeDoc(doc);

	return ret;
}

static void print_structure(FILE *manfile, char *refid, char *name)
{
	struct struct_info *si;
	struct param_info *pi;
	qb_map_iter_t *iter;
	const char *p;
	void *data;
	int max_param_length=0;

	/* If it's not been read in - go and look for it */
	si = qb_map_get(structures_map, refid);
	if (!si) {
		if (!read_structure_from_xml(refid, name)) {
			si = qb_map_get(structures_map, refid);
		}
	}

	if (si) {
		iter = qb_map_iter_create(si->params_map);
		for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
			pi = data;
			if (strlen(pi->paramtype) > max_param_length) {
				max_param_length = strlen(pi->paramtype);
			}
		}
		qb_map_iter_free(iter);

		fprintf(manfile, "struct %s {\n", si->structname);

		iter = qb_map_iter_create(si->params_map);
		for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
			pi = data;
			fprintf(manfile, "   %-*s \\fI%s\\fP;\n", max_param_length, pi->paramtype, pi->paramname);
		}
		qb_map_iter_free(iter);
		fprintf(manfile, "};\n");
	}
}

char *get_texttree(int *type, xmlNode *cur_node, char **returntext)
{
	xmlNode *this_tag;
	char *tmp;
	char buffer[4096] = {'\0'};

	for (this_tag = cur_node->children; this_tag; this_tag = this_tag->next) {

		if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "para") == 0) {
			tmp = get_text(this_tag, returntext);
			strcat(buffer, tmp);
			strcat(buffer, "\n");
			free(tmp);
		}
	}

	if (buffer[0]) {
		tmp = strdup(buffer);
	}

	return tmp;
}

/* The text output is VERY basic and just a check that it's working really */
static void print_text(char *name, char *def, char *brief, char *args, char *detailed, qb_map_t *param_map, char *returntext)
{
	printf(" ------------------ %s --------------------\n", name);
	printf("NAME\n");
	printf("        %s - %s", name, brief);

	printf("SYNOPSIS\n");
	printf("        %s %s\n\n", name, args);

	printf("DESCRIPTION\n");
	printf("        %s\n", detailed);

	printf("RETURN VALUE\n");
	printf("        %s\n", returntext);
}

/* Print a long string with para marks in it. */
static void man_print_long_string(FILE *manfile, char *text)
{
	char *next_nl;
	char *current = text;

	next_nl = strchr(text, '\n');
	while (next_nl && *next_nl != '\0') {
		*next_nl = '\0';
		fprintf(manfile, "%s\n.PP\n", current);

		*next_nl = '\n';
		current = next_nl+1;
		next_nl = strchr(current, '\n');
	}
}

static void print_manpage(char *name, char *def, char *brief, char *args, char *detailed, qb_map_t *param_map, char *returntext)
{
	char manfilename[PATH_MAX];
	char gendate[64];
	FILE *manfile;
	time_t t;
	struct tm *tm;
	qb_map_iter_t *iter;
	const char *p;
	void *data;
	int max_param_type_len;
	int max_param_name_len;
	int num_param_descs;
	int param_count;
	int param_num;
	struct param_info *pi;

	t = time(NULL);
	tm = localtime(&t);
	if (!tm) {
		perror("unable to get localtime"); // TODO Better handling
		return;
	}
	strftime(gendate, sizeof(gendate), "%Y-%m-%d", tm);

	snprintf(manfilename, sizeof(manfilename), "%s/%s.%s", output_dir, name, man_section);
	manfile = fopen(manfilename, "w+");
	if (!manfile) {
		perror("unable to open output file"); // TODO Better handling
		printf("%s", manfilename); // TODO Better handling
		exit(1);
	}

	/* Work out the length of the parameters, so we can line them up   */
	max_param_type_len = 0;
	max_param_name_len = 0;
	num_param_descs = 0;
	iter = qb_map_iter_create(param_map);
	for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
		pi = data;

		if (strlen(pi->paramtype) > max_param_type_len) {
			max_param_type_len = strlen(pi->paramtype);
		}
		if (strlen(pi->paramname) > max_param_name_len) {
			max_param_name_len = strlen(pi->paramname);
		}
		if (pi->paramdesc) {
			num_param_descs++;
		}
		param_count++;
	}
	qb_map_iter_free(iter);

	/* Off we go */

	fprintf(manfile, ".\\\"  Automatically generated man page, do not edit\n");
	fprintf(manfile, ".TH %s %s %s \"%s\" \"%s\"\n", name, man_section, gendate, package_name, header);

	fprintf(manfile, ".SH \"NAME\"\n");
	fprintf(manfile, "%s \\- %s\n", name, brief);

	fprintf(manfile, ".SH \"SYNOPSIS\"\n");
	fprintf(manfile, ".nf\n");
	fprintf(manfile, ".B #include <libknet.h>\n");
	fprintf(manfile, ".sp\n");
	fprintf(manfile, "\\fB%s\\fP(\n", def);

	iter = qb_map_iter_create(param_map);
	for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
		pi = data;

		fprintf(manfile, "    \\fB%-*s \\fP\\fI%s\\fP%s\n", max_param_type_len, pi->paramtype, p,
			param_num++ < param_count?",":"");
	}
	qb_map_iter_free(iter);

	fprintf(manfile, ");\n");
	fprintf(manfile, ".fi\n");

	if (print_params && num_param_descs) {
		fprintf(manfile, ".SH \"PARAMS\"\n");
		iter = qb_map_iter_create(param_map);
		for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
			pi = data;

			fprintf(manfile, "\\fB%-*s \\fP\\fI%s\\fP\n", max_param_name_len, pi->paramname,
				pi->paramdesc);
			fprintf(manfile, ".PP\n");
		}
		qb_map_iter_free(iter);
	}

	fprintf(manfile, ".SH \"DESCRIPTION\"\n");
	man_print_long_string(manfile, detailed);

	if (qb_map_count_get(used_structures_map)) {
		fprintf(manfile, ".SH \"STRUCTURES\"\n");


		iter = qb_map_iter_create(used_structures_map);
		for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
			fprintf(manfile, ".SS \"\"\n");
			fprintf(manfile, ".PP\n");
			fprintf(manfile, ".sp\n");
			fprintf(manfile, ".sp\n");
			fprintf(manfile, ".RS\n");
			fprintf(manfile, ".nf\n");
			fprintf(manfile, "\\fB\n");

			print_structure(manfile, (char*)p, (char *)data);

			fprintf(manfile, "\\fP\n");
			fprintf(manfile, ".fi\n");
		}
		qb_map_iter_free(iter);

		fprintf(manfile, ".RE\n");
	}

	fprintf(manfile, ".SH \"RETURN VALUE\"\n");
	man_print_long_string(manfile, returntext);
	fprintf(manfile, ".PP\n");

	iter = qb_map_iter_create(retval_map);
	for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
		pi = data;

		fprintf(manfile, "\\fB%-*s \\fP\\fI%s\\fP\n", 10, pi->paramname,
			pi->paramdesc);
		fprintf(manfile, ".PP\n");
	}
	qb_map_iter_free(iter);

	fprintf(manfile, ".SH \"SEE ALSO\"\n");
	fprintf(manfile, ".PP\n");
	fprintf(manfile, ".nh\n");
	fprintf(manfile, ".ad l\n");

	iter = qb_map_iter_create(function_map);
	for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {

		/* Exclude us! */
		if (strcmp(data, name)) {
			fprintf(manfile, "\\fI%s(%s)%s", (char *)data, man_section,
				param_num++ <= (num_functions)?", ":"");
		}
	}
	qb_map_iter_free(iter);

	fprintf(manfile, "\n");
	fprintf(manfile, ".ad\n");
	fprintf(manfile, ".hy\n");
	fprintf(manfile, ".SH \"COPYRIGHT\"\n");
	fprintf(manfile, ".PP\n");
	fprintf(manfile, "Copyright (C) 2010-%4d Red Hat, Inc. All rights reserved\n", tm->tm_year+1900);
	fclose(manfile);

	/* Free the params info */
	iter = qb_map_iter_create(param_map);
	for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
		pi = data;
		qb_map_rm(param_map, p);
		free_paraminfo(pi);
	}
	qb_map_iter_free(iter);

	iter = qb_map_iter_create(retval_map);
	for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
		pi = data;
		qb_map_rm(retval_map, p);
		free_paraminfo(pi);
	}
	qb_map_iter_free(iter);

	/* Free used-structures map */
	iter = qb_map_iter_create(used_structures_map);
	for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
		qb_map_rm(used_structures_map, p);
		free(data);
	}
}

/* Same as traverse_members, but to collect function names */
void collect_functions(xmlNode *cur_node, void *arg)
{
	xmlNode *this_tag;
	char *kind;
	char *name;

	if (cur_node->name && strcmp((char *)cur_node->name, "memberdef") == 0) {

		kind = get_attr(cur_node, "kind");
		if (kind && strcmp(kind, "function") == 0) {

			for (this_tag = cur_node->children; this_tag; this_tag = this_tag->next) {
				if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "name") == 0) {
					name = strdup((char *)this_tag->children->content);
				}
			}

			qb_map_put(function_map, name, name);
			num_functions++;
		}
	}
}


void traverse_members(xmlNode *cur_node, void *arg)
{
	xmlNode *this_tag;

	if (cur_node->name && strcmp((char *)cur_node->name, "memberdef") == 0) {
		char *kind;
		char *def;
		char *args;
		char *name;
		char *brief;
		char *detailed;
		char *returntext;
		int type;

		kind=def=args=name=NULL;

		kind = get_attr(cur_node, "kind");

		for (this_tag = cur_node->children; this_tag; this_tag = this_tag->next)
		{
			if (!this_tag->children || !this_tag->children->content)
				continue;

			if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "definition") == 0)
				def = strdup((char *)this_tag->children->content);
			if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "argsstring") == 0)
				args = strdup((char *)this_tag->children->content);
			if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "name") == 0)
				name = strdup((char *)this_tag->children->content);

			if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "briefdescription") == 0) {
	                       brief = get_texttree(&type, this_tag, &returntext);
			}
			if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "detaileddescription") == 0) {
				detailed = get_texttree(&type, this_tag, &returntext);
			}
			/* Get all the params */
			if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "param") == 0) {
				char *param_type = get_child(this_tag, "type");
				char *param_name = get_child(this_tag, "declname");
				struct param_info *pi = malloc(sizeof(struct param_info));
				if (pi) {
					pi->paramname = param_name;
					pi->paramtype = param_type;
					pi->paramdesc = NULL;
					qb_map_put(params_map, param_name, pi);
				}
			}
		}

		if (kind && strcmp(kind, "typedef") == 0) {
			/* Collect typedefs? */
		}

		if (kind && strcmp(kind, "function") == 0) {
			if (print_man) {
				print_manpage(name, def, brief, args, detailed, params_map, returntext);
			}
			else {
				print_text(name, def, brief, args, detailed, params_map, returntext);
			}

		}

		free(kind);
		free(def);
		free(args);
//		free(name); /* don't free, it's in the map */
	}
}


static void traverse_node(xmlNode *parentnode, char *leafname, void (do_members(xmlNode*, void*)), void *arg)
{
	xmlNode *cur_node;

	for (cur_node = parentnode->children; cur_node; cur_node = cur_node->next) {

		if (cur_node->type == XML_ELEMENT_NODE && cur_node->name
		    && strcmp((char*)cur_node->name, leafname)==0) {
			do_members(cur_node, arg);
			continue;
		}
		if (cur_node->type == XML_ELEMENT_NODE) {
			traverse_node(cur_node, leafname, do_members, arg);
		}
	}
}


static void usage(char *name)
{
	printf("Usage:\n");
	printf("      %s -[am] [-s <section>] [-p<packagename>] [-H <header>] [-o <output dir>] [XML file]\n", name);
	printf("\n");
	printf("       -a            Print ASCII dump of man pages to stdout\n");
	printf("       -n            Write man page files to <output dir>\n");
	printf("       -P            Print PARAMS section\n");
	printf("       -s <s>        Write man pages into section <s> <default 3)\n");
	printf("       -p <package>  Use <package> name. default <Kronosnet>\n");
	printf("       -H <header>   Set header (default \"Kronosnet Programmer's Manual\"\n");
	printf("       -o <dir>      Write all man pages to <dir> (default .)\n");
	printf("       -d <dir>      Directory for XML files\n");
	printf("       -h            Print this usage text\n");
}

int main(int argc, char *argv[])
{
	xmlNode *rootdoc;
	xmlDocPtr doc;
	int quiet=0;
	int opt;
	char xml_filename[PATH_MAX];

	while ( (opt = getopt_long(argc, argv, "amPs:d:o:p:f:h?", NULL, NULL)) != EOF)
	{
		switch(opt)
		{
			case 'a':
				print_ascii = 1;
				print_man = 0;
				break;
			case 'm':
				print_man = 1;
				print_ascii = 0;
				break;
			case 'P':
				print_params = 1;
				break;
			case 's':
				man_section = optarg;
				break;
			case 'd':
				xml_dir = optarg;
				break;
			case 'p':
				package_name = optarg;
				break;
			case 'H':
				header = optarg;
				break;
			case 'o':
				output_dir = optarg;
				break;
			case '?':
			case 'h':
				usage(argv[0]);
				return 0;
		}
	}

	if (argv[optind]) {
		xml_file = argv[optind];
	}
	if (!quiet) {
		fprintf(stderr, "reading xml ... ");
	}

	snprintf(xml_filename, sizeof(xml_filename), "%s/%s", xml_dir, xml_file);
	doc = xmlParseFile(xml_filename);
	if (doc == NULL) {
		fprintf(stderr, "Error: unable to read xml file %s\n", xml_filename);
		exit(1);
	}

	rootdoc = xmlDocGetRootElement(doc);
	if (!rootdoc) {
		fprintf(stderr, "Can't find \"document root\"\n");
		exit(1);
	}
	if (!quiet)
		fprintf(stderr, "done.\n");

	params_map = qb_hashtable_create(10);
	retval_map = qb_hashtable_create(10);
	used_structures_map = qb_hashtable_create(10);
	structures_map = qb_hashtable_create(50);
	function_map = qb_hashtable_create(100);

	/* Collect functions */
	traverse_node(rootdoc, "memberdef", collect_functions, NULL);

	/* print pages */
	traverse_node(rootdoc, "memberdef", traverse_members, NULL);

	return 0;
}
