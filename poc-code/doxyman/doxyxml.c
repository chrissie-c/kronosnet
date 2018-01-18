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

#define TAG_TYPE_PARA       1
#define TAG_TYPE_TEXT       2
#define TAG_TYPE_TYPE       3
#define TAG_TYPE_SIMPLESECT 4
#define TAG_TYPE_DECLNAME   5

static int print_ascii = 1;
static int print_man = 0;
static char *man_section="3";
static char *package_name="Kronosnet";
static char *footer="Kronosnet Programmer's Manual";
static char *output_dir="";
static qb_map_t *params_map;
static qb_map_t *function_map;

static char *get_texttree(int *type, xmlNode *cur_node, char **returntext);

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

	for (this_node = node->children; this_node; this_node = this_node->next) {
		if (this_node->type == XML_ELEMENT_NODE && this_node->children && strcmp((char *)this_node->name, tag) == 0) {
			return strdup((char *)this_node->children->content);
		}
	}
	return NULL;
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

char *get_text(xmlNode *cur_node, char **returntext)
{
	xmlNode *this_tag;
	char *kind;
	char buffer[4096] = {'\0'};

	for (this_tag = cur_node->children; this_tag; this_tag = this_tag->next) {
		if (this_tag->type == XML_TEXT_NODE && strcmp((char *)this_tag->name, "text") == 0) {
			if (not_all_whitespace((char*)this_tag->content)) {
				strcat(buffer, (char*)this_tag->content);
				strcat(buffer, "\n");
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
	}
	return strdup(buffer);
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

		// PARAMs ??? CC is this right??x
		if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "type") == 0 &&
			this_tag->children->content) {
			*type = TAG_TYPE_TYPE;
			tmp = strdup((char*)this_tag->children->content);
		}
		if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "declname") == 0 &&
		    this_tag->children->content) {
			*type = TAG_TYPE_DECLNAME;
			tmp = strdup((char*)this_tag->children->content);
		}
	}
	if (buffer[0]) {
		tmp = strdup(buffer);
	}

	return tmp;
}

static void print_text(char *name, char *def, char *brief, char *args, char *detailed, qb_map_t *param_map, char *returntext)
{
	printf(" ------------------ Header --------------------\n");
	printf("NAME\n");
	printf("        %s - %s", name, brief);

	printf("SYNOPSIS\n");
	printf("        %s %s\n\n", name, args);

	printf("DESCRIPTION\n");
	printf("        %s\n", detailed);

	printf("RETURN VALUE\n");
	printf("        %s\n", returntext);
}

static void man_print_long_string(FILE *manfile, char *text)
{
	fprintf(manfile, text);// TODO
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
	int max_param_len;
	int param_count;
	int param_num;

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
		return;
	}

	fprintf(manfile, ".\\\"  Automatically generated man page, do not edit\n");
	fprintf(manfile, ".TH %s %s %s \"%s\" \"%s\"\n", name, man_section, gendate, package_name, footer);

	fprintf(manfile, ".SH \"NAME\"\n");
	fprintf(manfile, "%s \\- %s\n", name, brief);

	fprintf(manfile, ".SH \"SYNOPSIS\"\n");
	fprintf(manfile, ".nf\n");
	fprintf(manfile, ".B #include <libknet.h>\n");
	fprintf(manfile, ".sp\n");
	fprintf(manfile, "\\fB%s\\fP(\n", def);

	max_param_len = 0;
	iter = qb_map_iter_create(param_map);
	for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
		if (strlen(p) > max_param_len) {
			max_param_len = strlen(p);
		}
		param_count++;
	}
	qb_map_iter_free(iter);

	iter = qb_map_iter_create(param_map);
	for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
		fprintf(manfile, "    \\fB%-*s \\fP\\fI%s\\fP%s\n", max_param_len, p, (char*) data,
			param_num++ < param_count?",":"");
		qb_map_rm(param_map, p);
	}
	qb_map_iter_free(iter);

	fprintf(manfile, ");\n");
	fprintf(manfile, ".fi\n");

	fprintf(manfile, ".SH \"DESCRIPTION\"\n");
	man_print_long_string(manfile, detailed);

	fprintf(manfile, ".SH \"RETURN VALUE\"\n");
	man_print_long_string(manfile, returntext);

#if 0
	fprintf(manfile, ".SH \"SEE ALSO\"\n");
	fprintf(manfile, ".PP\n");
	fprintf(manfile, ".nh\n");
	fprintf(manfile, ".ad l\n");

	/* This is no use as we print the functions as we gather them!! */
	iter = qb_map_iter_create(function_map);
	for (p = qb_map_iter_next(iter, &data); p; p = qb_map_iter_next(iter, &data)) {
		fprintf(manfile, "\\fI%s(%s)%s", (char *)data, man_section,
			param_num++ < param_count?", ":"");
		qb_map_rm(param_map, p);
	}
	qb_map_iter_free(iter);
#endif

	fprintf(manfile, ".ad\n");
	fprintf(manfile, ".hy\n");
	fprintf(manfile, ".SH \"COPYRIGHT\"\n");
	fprintf(manfile, ".PP\n");
	fprintf(manfile, "Copyright (C) 2010-%4d Red Hat, Inc. All rights reserved\n", tm->tm_year+1900);
	fclose(manfile);
}

void traverse_members(xmlNode *cur_node)
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
			if (this_tag->type == XML_ELEMENT_NODE && strcmp((char *)this_tag->name, "param") == 0) {
				char *param_type = get_child(this_tag, "type");
				char *param_name = get_child(this_tag, "declname");
				qb_map_put(params_map, param_name, param_type);
			}
		}

		if (kind && strcmp(kind, "typedef") == 0) {
			/* Collect typedefs? */
		}

		if (kind && strcmp(kind, "function") == 0) {

			qb_map_put(function_map, man_section, name);
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


void traverse_node(xmlNode *parentnode, char *leafname)
{
	xmlNode *cur_node;

	for (cur_node = parentnode->children; cur_node; cur_node = cur_node->next) {
//		fprintf(stderr, "Node: %s\n",(char *)cur_node->name);

		if (cur_node->type == XML_ELEMENT_NODE && cur_node->name
		    && strcmp((char*)cur_node->name, leafname)==0) {
			traverse_members(cur_node);
			continue;
		}
		if (cur_node->type == XML_ELEMENT_NODE) {
			traverse_node(cur_node, leafname);
		}
	}
}


int main(int argc, char *argv[])
{
	xmlNode *tweets;
	xmlDocPtr doc;
	int quiet=0;
	int opt;

	while ( (opt = getopt_long(argc, argv, "ams:o:p:f:h?", NULL, NULL)) != EOF)
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
			case 's':
				man_section = optarg;
				break;
			case 'p':
				package_name = optarg;
				break;
			case 'f':
				footer = optarg;
				break;
			case 'o':
				output_dir = optarg;
				break;
			case '?':
			case 'h':
				//usage();
				break;
		}
	}

	if (!quiet) {
		fprintf(stderr, "reading xml ... ");
	}

	doc = xmlParseFile("../../libknet/man/xml/libknet_8h.xml");
	if (doc == NULL) {
		fprintf(stderr, "Error: unable to parse xml file\n");
		exit(1);
	}

	tweets = xmlDocGetRootElement(doc);
	if (!tweets) {
		fprintf(stderr, "Can't find \"document root\"\n");
		exit(1);
	}
	if (!quiet)
		fprintf(stderr, "done.\n");

	params_map = qb_hashtable_create(10);
	function_map = qb_hashtable_create(100);
	traverse_node(tweets, "memberdef");

	return 0;
}
