#ifndef _CALLBACKS_H_
#define _CALLBACKS_H_

#include "../dialog/dlg_hash.h"

#include "common.h"

atomic_t* export_looped_msg;

void consider_exporting(struct dlg_cell* dlg, int type, struct dlg_cb_params *params);

#endif	/* _CALLBACKS_H_ */

