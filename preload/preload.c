#define _GNU_SOURCE

#include "config.h"

//Net stuff
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

//PAM stuff
#include <security/pam_appl.h>

//Dynamic Library stuff
#include <dlfcn.h>

//Libconfig
#include <libconfig.h>

//Standard C stuff
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

typedef struct linkedList
{
	const char *value;
	struct linkedList *next;

} linkedList_t;

void freeLinkedList(linkedList_t *list)
{
	linkedList_t *top = list;
  linkedList_t *next = top -> next;

  while(next != NULL)
  {
    free(top);
    top = next;
    next = next -> next;
  }
  free(top);
}

int pam_start(const char *service_name, const char *user,
	     const struct pam_conv *pam_conversation,
	     pam_handle_t **pamh)
{
  printf("In pam_start: %s\n", service_name);
  int (*original_pam_start)(const char *service_name, const char *user,
	     const struct pam_conv *pam_conversation,
	     pam_handle_t **pamh);
  original_pam_start = dlsym(RTLD_NEXT, "pam_start");
  return (*original_pam_start)(service_name, user, pam_conversation, pamh);

}

int pam_end(pam_handle_t *pamh, int pam_status)
{
  printf("In pam_end\n");
  int (*original_pam_end)(pam_handle_t *pamh, int pam_status);
  original_pam_end = dlsym(RTLD_NEXT, "pam_end");
  return (*original_pam_end)(pamh, pam_status);
}

int getaddrinfo(const char *restrict node,
               const char *restrict service,
               const struct addrinfo *restrict hints,
               struct addrinfo **restrict res)
{
	const char *rawValue = NULL;

  int (*original_getaddrinfo)(const char *restrict node,
                               const char *restrict service,
                               const struct addrinfo *restrict hints,
                               struct addrinfo **restrict res);
  original_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");


  linkedList_t *safeHostsList = malloc(sizeof(linkedList_t));
  safeHostsList -> next = NULL;
  config_t config;

  config_init(&config);
  //If we can't open the config, then just fail
  if(!config_read_file(&config, SAFE_HOSTS_PATH))
  {
    fprintf(stderr, "error file = %s, error line = %d, error text = %si\n",
      config_error_file(&config),
      config_error_line(&config),
      config_error_text(&config));
    
    config_destroy(&config);
    return EAI_FAIL;
  }

  //strncmp was causing a segfault when node was 0x00
  if(node == NULL)
  {
    return (*original_getaddrinfo)(node, service, hints, res);
  }

  if(config_lookup_string(&config,"hosts",&rawValue))
	{
			printf("%s=%s\n", "hosts", rawValue);
      
      int difference = strncmp(rawValue, node, strlen(rawValue));
      if(difference == 0)
      {
        return (*original_getaddrinfo)(node, service, hints, res);
      }
      else
      {
        fprintf(stderr, "Different strings at %s - %s = %i\n", rawValue, node, difference);
        return EAI_FAIL;
      }

	}
	else
	{
			fprintf(stderr, "no hosts set\n");
	}

	config_destroy(&config);

  puts("Hello World!");
  printf("Reaching out to: %s\n", node);

}
