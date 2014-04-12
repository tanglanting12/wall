#ifndef _GTK_WINDOW_VIEW_
#define _GTK_WINDOW_VIEW_

#include <gtk/gtk.h>
#include <linux/netfilter_ipv4/nf_nat.h>
#include "netfilter_utils.h"

/** 
 * for client to check current toolbar status
 * which toolbar item using
 * now there are four
 */
typedef enum {
	IP_FILTER,
	NETWORK_TRACK,
	ADDRESS_TRANSLATE,
	ABOUT_US
} view_status_t;

/** flag to the status */
static view_status_t curr_view_type = IP_FILTER;
// the view's main container
static GtkWidget *main_container = NULL;
// the data view that can change, also for remove
static GtkWidget *show_content = NULL;


/** create the main window */
GtkWidget* create_win();

/** win is for accel_group to add */
GtkWidget* create_menu(GtkWidget *win);

/** create the toolbar */
GtkWidget* create_toolbar();

/** create the statusbar */
GtkWidget* create_statusbar();

/** menubar item activate event callback */
void menubar_item_activate(GtkWidget *item, gpointer p);

/** toolbar item click event callback*/
void toolbar_item_activate(GtkWidget *item, gpointer p);

/** set statusbar text */
void set_statusbar_text(GtkWidget *statusbar, char *text);

/** destroy callback */
void win_destroy(GtkWidget *win, gpointer p);

/** 
 * create the dialog
 * @title:     the title of the dialog
 * @message:   the message show on content
 * @is_ok:     is show the ok btn
 * @is_cancel: is show the canel btn
 * @ok:        if is_ok set, the ok btn would reference
 * @cancel:    same as the ok
 */
GtkWidget* create_dialog(gchar *title, gchar *message, 
		gboolean is_ok, gboolean is_cancel, GtkWidget **ok, GtkWidget **cancel);

/** the default dialog btn callback */
void common_dialog_btn_callback(GtkWidget *widget, gpointer p);

/** show or dismiss widget */
void show_widget(GtkWidget* widget);
void dismiss_widget(GtkWidget *widget);

/** create the about us dialog */
void show_about_dialog();

/** 
 * create the IP filter content
 * @container: the main vbox container
 * @return:    the content box, is for remove if the 
 *             toolbar click to changes the content
 */
GtkWidget* show_ip_filter(GtkWidget *container);
/** ip content some widget call back */
void filter_action_callback(GtkWidget *widget, gpointer p);

/** 
 * create the clist
 * @title:  clist titles
 * @colunm: colunm size
 */
GtkWidget* create_clist(gchar **titles, gint column);

/** 
 * add datas to clist;
 * @clist:  the widget
 * @head:   the data link's head
 * @column: size of the column
 */
void clist_add_datas(GtkWidget *clist, ip_link_t *head, gint column);

/**
 * create the net track list
 * @container: the main vbox contianer
 * @return:    the content box, if for remove if the
 *             toolbar click to changes the content
 */
GtkWidget* show_network_track(GtkWidget *container);

/**
 * start or stop track for the btn callback
 */
void start_track(GtkWidget *widget, gpointer p);
void stop_track(GtkWidget *widget, gpointer p);

/**
 * create the show address translate view
 * @container: the main vbox contianer
 * @return:    the content box, if for remove if the
 *             toolbar click to changes the content
 */
GtkWidget *show_addr_translate(GtkWidget *container);

/**
 * for list double click to remove the item
 */
gboolean rm_list_item_callback(GtkWidget *widget, 
		GdkEvent *event, gpointer p);

/** net action callback, include the toggle_btn and add btn  */
void net_action_callback(GtkWidget *widget, gpointer p);

/** 
 * this for client to init the windows 
 * @argc:           pass by the main
 * @argv:           pass by the main
 * @statusbar_text: to show on the statusbar
 * @device:         current work network device
 */
void init_views(int argc, char **argv, char *statusbar_text,
		char *device);

#endif
