#include "dt.h"
#include <assert.h>
#include "../../mem/shm_mem.h"




struct dt_node_t {
	struct dt_node_t *child[10];
	char leaf;
};




static struct dt_node_t *dt_root = NULL;




int dt_init(void)
{
	dt_root = shm_malloc(sizeof(struct dt_node_t));
	if (dt_root == NULL) {
		LM_CRIT("cannot allocate memory for d-tree.\n");
		return -1;
	}

	memset(dt_root, 0, sizeof(struct dt_node_t));

	return 0;
}




void dt_delete(struct dt_node_t *node)
{
	int i;
	if (node==NULL) return;

	for (i=0; i<10; i++) {
		dt_delete(node->child[i]);
		node->child[i] = NULL;
	}

	if (node != dt_root) shm_free(node);
}




void dt_destroy(void)
{
	if (dt_root) {
		dt_delete(dt_root);
		shm_free(dt_root);
		dt_root = NULL;
	}
}




void dt_clear(void)
{
	dt_delete(dt_root);
}




void dt_insert(const char *number)
{
	struct dt_node_t *node = dt_root;

	int i=0;
	while (number[i]!=0) {
		unsigned int digit = number[i] - '0';
		if (digit>9) {
			LM_ERR("cannot insert non-numerical number");
			return;
		}
		if (node->child[digit] == NULL) {
			node->child[digit] = shm_malloc(sizeof(struct dt_node_t));
			assert(node->child[digit] != NULL);
			memset(node->child[digit], 0, sizeof(struct dt_node_t));
		}
		node = node->child[digit];

		i++;
	}

	node->leaf = 1;
}




int dt_contains(const char *number)
{
	struct dt_node_t *node = dt_root;

	int i=0;
	while (number[i]!=0) {
		unsigned int digit = number[i] - '0';
		if (digit>9) return 0;
		if (node->child[digit] == NULL) return 0;
		node = node->child[digit];

		i++;
	}

	if (node->leaf == 1) return 1;
	return 0;
}
