#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "gtk_win_view.h"
#include "global_variables.h"

extern view_status_t curr_view_type;
// the view's main container
extern GtkWidget *main_container;
// the data view that can change, also for remove
extern GtkWidget *show_content;

static GtkWidget *ipfilter_widget = NULL;
static GtkWidget *nettrack_widget = NULL;
static GtkWidget *translate_widget = NULL;

// the update ui thread contiue flag
static int p_flag = 0;
static const char *device = NULL;

struct addr_entry {
	GtkWidget *list;
	GtkEntry *entry1;
	GtkEntry *entry2;
	GtkEntry *entry3;
	GtkEntry *entry4;
};

struct delete_entry {
	// index = -1, if there are no any rule to delete
	int index;
	char table_name[20];
	char chain_name[20];
};

struct addr_entry ip_datas;
struct delete_entry delete_rule;

// pre declare the func for refresh_list_datas use
void init_addr_translate(GtkWidget *list);


/** create the main window */
GtkWidget* create_win()
{
	GtkWidget *win;

	win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(win), WIN_WIDTH, WIN_HEIGHT);
	gtk_window_set_title(GTK_WINDOW(win), WIN_NAME);
	gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
	gtk_window_set_icon(
			GTK_WINDOW(win), 
			gdk_pixbuf_new_from_file(APP_ICON_PATH, NULL));
	gtk_window_unmaximize(GTK_WINDOW(win));
	gtk_window_unfullscreen(GTK_WINDOW(win));
	gtk_signal_connect(
			GTK_OBJECT(win), 
			"destroy", 
			GTK_SIGNAL_FUNC(win_destroy), 
			NULL);

	return win;
}

/** win is for accel_group to add */
GtkWidget* create_menu(GtkWidget *win)
{
	GtkWidget *menubar;
	GtkWidget *menu;
	GtkWidget *help_item;
	GtkWidget *file_item;
	GtkWidget *item;
	GtkAccelGroup *accel_group;

	menubar = gtk_menu_bar_new();
	accel_group = gtk_accel_group_new();
	gtk_window_add_accel_group(GTK_WINDOW(win), accel_group);

	file_item = gtk_menu_item_new_with_label("文件");
	gtk_menu_bar_append(GTK_MENU_BAR(menubar), file_item);

	menu = gtk_menu_new();
	item = gtk_menu_item_new_with_label("退出");
	gtk_widget_set_name(item, "EXIT");
	gtk_menu_append(GTK_MENU(menu), item);
	gtk_widget_add_accelerator(item, "activate", accel_group, 'E',
			GDK_CONTROL_MASK | GDK_SHIFT_MASK, GTK_ACCEL_VISIBLE);
	gtk_signal_connect(GTK_OBJECT(item), "activate",
			GTK_SIGNAL_FUNC(menubar_item_activate), win);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(file_item), menu);

	help_item = gtk_menu_item_new_with_label("帮助");
	gtk_menu_bar_append(GTK_MENU_BAR(menubar), help_item);

	menu = gtk_menu_new();
	item = gtk_menu_item_new_with_label("使用帮助");
	gtk_menu_append(GTK_MENU(menu), item);
	gtk_widget_set_name(item, "HOW");
	gtk_widget_add_accelerator(item, "activate", accel_group, 'H',
			GDK_CONTROL_MASK | GDK_SHIFT_MASK, GTK_ACCEL_VISIBLE);
	gtk_signal_connect(GTK_OBJECT(item), "activate",
			GTK_SIGNAL_FUNC(menubar_item_activate), win);
	item = gtk_menu_item_new_with_label("关于");
	gtk_widget_set_name(item, "ABOUT");
	gtk_menu_append(GTK_MENU(menu), item);
	gtk_widget_add_accelerator(item, "activate", accel_group, 'A',
			GDK_CONTROL_MASK | GDK_SHIFT_MASK, GTK_ACCEL_VISIBLE);
	gtk_signal_connect(GTK_OBJECT(item), "activate",
			GTK_SIGNAL_FUNC(menubar_item_activate), win);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(help_item), menu);

	return menubar;
}

/** create the toolbar*/
GtkWidget* create_toolbar()
{
	GtkWidget *toolbar;
	GtkWidget *image;
	GdkPixbuf *buf;
	int i = 0;

	toolbar = gtk_toolbar_new();
	gtk_toolbar_set_style(GTK_TOOLBAR(toolbar), GTK_TOOLBAR_BOTH);
	for(i = 0; i < SIZE; ++i)
	{
		buf = gdk_pixbuf_scale_simple(
				gdk_pixbuf_new_from_file(IMAGE_PATHS[i], NULL),
				24, 24,
				GDK_INTERP_BILINEAR);

		image = gtk_image_new_from_pixbuf(buf);
		gtk_toolbar_append_item(
				GTK_TOOLBAR(toolbar),
				TITLES[i],
				TITLES[i],
				NULL,
				image,
				(GtkSignalFunc) toolbar_item_activate,
				TITLES[i]);
		// the horizontal splite line between the third and forth
		if(2 == i) {
			gtk_toolbar_append_space(GTK_TOOLBAR(toolbar));
		}
	}

	return toolbar;
}

/** create the statusbar*/
GtkWidget* create_statusbar()
{
	GtkWidget *statusbar;
	// guint context;
	statusbar = gtk_statusbar_new();
	gtk_statusbar_get_context_id(
			GTK_STATUSBAR(statusbar), "STATUS");
	return statusbar;
}

/** menubar item activate event callback*/
void menubar_item_activate(GtkWidget *item, gpointer p)
{
	const char *name = gtk_widget_get_name(item);
	if(!strcmp(name, "EXIT")) 
	{
		gtk_widget_destroy((GtkWidget*) p);
	}
	else if(!strcmp(name, "ABOUT"))
	{
		show_about_dialog();
	}
	else if(!strcmp(name, "HOW"))
	{
		// TODO fix the code
		g_print(">>> Click The How <<< \n");
	}
	else 
	{
		g_print(">>> wrong parames <<< \n");
	}
}

/** toolbar item click event callback*/
void toolbar_item_activate(GtkWidget *item, gpointer p)
{
	const gchar* tip = (gchar*) p;
	if(!strcmp(TITLES[0], tip))
	{
		if(curr_view_type == IP_FILTER)
		{
			return;
		}
		// to let the current ui update thread stop
		p_flag = 0;
		gtk_container_remove(GTK_CONTAINER(main_container), show_content);
		show_content = show_ip_filter(main_container);
		gtk_box_pack_start(GTK_BOX(main_container), show_content, TRUE, TRUE, 0);
		curr_view_type = IP_FILTER;
	}
	else if(!strcmp(TITLES[1], tip))
	{
		if(curr_view_type == NETWORK_TRACK)
		{
			return;
		}
		gtk_container_remove(GTK_CONTAINER(main_container), show_content);
		show_content = show_network_track(main_container);
		gtk_box_pack_start(GTK_BOX(main_container), show_content, TRUE, TRUE, 0);
		curr_view_type = NETWORK_TRACK;
	}
	else if(!strcmp(TITLES[2], tip))
	{
		if(curr_view_type == ADDRESS_TRANSLATE)
		{
			return;
		}
		p_flag = 0;
		gtk_container_remove(GTK_CONTAINER(main_container), show_content);
		show_content = show_addr_translate(main_container);
		gtk_box_pack_start(GTK_BOX(main_container), show_content, TRUE, TRUE, 0);
		curr_view_type = ADDRESS_TRANSLATE;
	}
	else if(!strcmp(TITLES[3], tip))
	{
		curr_view_type = ABOUT_US;
		show_about_dialog();
	}
}

/** set statusbar text*/
void set_statusbar_text(GtkWidget *statusbar, char *text)
{
	gint context = gtk_statusbar_get_context_id(
			GTK_STATUSBAR(statusbar), "STATUS");
	gtk_statusbar_pop(
			GTK_STATUSBAR(statusbar),
			context);
	gtk_statusbar_push(
			GTK_STATUSBAR(statusbar),
			context,
			text);
}

/** destroy callback */
void win_destroy(GtkWidget *win, gpointer p)
{
	// kill the process
	gtk_main_quit();
}

/** create the dialog 
 * is_ok:     show the ok button
 * is_cancel: show the cancel button
 *            if true shown
 */
GtkWidget* create_dialog(gchar *title, gchar* message, 
		gboolean is_ok, gboolean is_cancel, 
		GtkWidget **ok, GtkWidget **cancel)
{
	GtkWidget *dialog;
	GtkWidget *image;
	GtkWidget *hbox;

	dialog = gtk_dialog_new();
	image = gtk_image_new_from_stock(GTK_STOCK_DIALOG_INFO, GTK_ICON_SIZE_DIALOG);
	hbox = gtk_hbox_new(FALSE, 5);

	gtk_window_set_title(GTK_WINDOW(dialog), title);
	gtk_container_set_border_width(GTK_CONTAINER(dialog), 10);
	gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_default_size(GTK_WINDOW(dialog), 360, 150);
	gtk_dialog_set_has_separator(GTK_DIALOG(dialog), TRUE);
	gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, TRUE, 5);
	gtk_box_pack_start(GTK_BOX(hbox), gtk_label_new(message), FALSE, TRUE, 5);
	gtk_box_pack_start_defaults(GTK_BOX(GTK_DIALOG(dialog)->vbox), hbox);
	// must be one button, if there ok and cancel both false
	// make the ok button is true
	is_ok = is_ok || is_cancel? is_ok : TRUE;
	if(is_cancel)
	{
		if(!*cancel) 
		{
			*cancel = gtk_button_new_with_label("取消");
		}
		gtk_widget_set_name(*cancel, "CANCEL");
		g_signal_connect(GTK_OBJECT(*cancel),
				"clicked",
				GTK_SIGNAL_FUNC(common_dialog_btn_callback),
				dialog);
		gtk_dialog_add_action_widget(GTK_DIALOG(dialog), *cancel, 1);
	}
	if(is_ok)
	{
		if(!*ok)
		{
			*ok = gtk_button_new_with_label("确定");
		}
		gtk_widget_set_name(*ok, "OK");
		g_signal_connect(GTK_OBJECT(*ok),
				"clicked",
				GTK_SIGNAL_FUNC(common_dialog_btn_callback),
				dialog);
		gtk_dialog_add_action_widget(GTK_DIALOG(dialog), *ok, 2);
	}
	// gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
	gtk_widget_show_all(dialog);
	return dialog;
}

// for dialog to remove the list item 
void common_dialog_btn_callback(GtkWidget *widget, gpointer p)
{
	const gchar *name = gtk_widget_get_name(widget);
	// delete the rule
	if(!strcmp(name, "OK") && delete_rule_at_index(
				delete_rule.table_name,
				delete_rule.chain_name, 
				delete_rule.index))
	{
		// current list which can view
		// is store in ip_datas.list;
		if(GTK_IS_CLIST(ip_datas.list))
		{
			gtk_clist_remove(GTK_CLIST(ip_datas.list), 
					GTK_CLIST(ip_datas.list)->focus_row);
		}
		else if(GTK_IS_LIST(ip_datas.list))
		{
			GtkWidget *widget = 
				gtk_container_get_focus_child(GTK_CONTAINER(ip_datas.list));
			gtk_container_remove(GTK_CONTAINER(ip_datas.list), widget);
		}
	}
	gtk_widget_destroy((GtkWidget*) p);
}

/** show and dissmiss the dialog */
void show_widget(GtkWidget *widget)
{
	gtk_widget_show(widget);
}

void dismiss_widget(GtkWidget *widget)
{
	gtk_widget_hide(widget);
}

/** show the about us dialog */
void show_about_dialog()
{
	GdkPixbuf *pixbuf = gdk_pixbuf_new_from_file(APP_ICON_PATH, NULL);
	GtkWidget *dialog = gtk_about_dialog_new();
	gtk_about_dialog_set_name(GTK_ABOUT_DIALOG(dialog), APP_NAME);
	gtk_about_dialog_set_version(GTK_ABOUT_DIALOG(dialog), "  v0.0.1"); 
	gtk_about_dialog_set_copyright(GTK_ABOUT_DIALOG(dialog), 
			"(c) Jayhoo Lin");
	gtk_about_dialog_set_comments(GTK_ABOUT_DIALOG(dialog), 
			"MINI Firewall 是一款简单的迷你防火墙");
	gtk_about_dialog_set_website(GTK_ABOUT_DIALOG(dialog), 
			"http://www.****.com");
	gtk_about_dialog_set_logo(GTK_ABOUT_DIALOG(dialog), pixbuf);
	g_object_unref(pixbuf), pixbuf = NULL;
	gtk_dialog_run(GTK_DIALOG (dialog));
	gtk_widget_destroy(dialog);
}

/** show the view of the ip filter */
GtkWidget* show_ip_filter(GtkWidget *container)
{
	GtkWidget *vbox;
	GtkWidget *input_box;
	GtkWidget *clist;
	GtkWidget *scroller;
	GtkWidget *btn;
	GtkWidget *entry_ip;
	GtkWidget *entry_port;

	gchar *title[] = {
		"来源地址", "来源端口", "目的地址", "目的端口", 
		"协议", "动作", "表", "链", "索引"
	};
	vbox = gtk_vbox_new(FALSE, 0);
	clist = create_clist(title, 9);
	ip_link_t *head = get_ip_all();
	clist_add_datas(clist, head, 9);
	free_ip_link(head);
	head = NULL;
	gtk_signal_connect(GTK_OBJECT(clist), 
			"button_press_event",
			GTK_SIGNAL_FUNC(rm_list_item_callback),
			NULL);
	scroller = gtk_scrolled_window_new(NULL,
			GTK_ADJUSTMENT(gtk_adjustment_new(0, 0, 0, 0, 0, 0)));
	gtk_container_add(GTK_CONTAINER(scroller), clist);
	gtk_box_pack_start(GTK_BOX(vbox), scroller, TRUE, TRUE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(clist), 8);

	input_box = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(input_box), 8);
	gtk_box_pack_start(GTK_BOX(vbox), input_box, FALSE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(input_box), 
			gtk_label_new("过滤的IP："), FALSE, TRUE, 0);
	entry_ip = gtk_entry_new_with_max_length(16);
	entry_port = gtk_entry_new_with_max_length(5);
	gtk_box_pack_start(GTK_BOX(input_box), entry_ip, FALSE, TRUE, 0);
	btn = gtk_check_button_new_with_label("TCP");
	gtk_signal_connect(GTK_OBJECT(btn), "toggled", 
			GTK_SIGNAL_FUNC(filter_action_callback), NULL);
	gtk_box_pack_start(GTK_BOX(input_box), btn, FALSE, TRUE, 2);
	btn = gtk_check_button_new_with_label("UDP");
	gtk_signal_connect(GTK_OBJECT(btn), "toggled", 
			GTK_SIGNAL_FUNC(filter_action_callback), NULL);
	gtk_box_pack_start(GTK_BOX(input_box), btn, FALSE, TRUE, 2);
	btn = gtk_check_button_new_with_label("ICMP");
	gtk_signal_connect(GTK_OBJECT(btn), "toggled",
			GTK_SIGNAL_FUNC(filter_action_callback), NULL);
	gtk_box_pack_start(GTK_BOX(input_box), btn, FALSE, TRUE, 2);
	btn = gtk_check_button_new_with_label("ALL PROTO");
	gtk_signal_connect(GTK_OBJECT(btn), "toggled", 
			GTK_SIGNAL_FUNC(filter_action_callback), NULL);
	gtk_box_pack_start(GTK_BOX(input_box), btn, FALSE, TRUE, 2);
	btn = gtk_button_new_with_label("添加");
	gtk_box_pack_start(GTK_BOX(input_box), btn, FALSE, TRUE, 4);
	input_box = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(input_box), 8);
	gtk_box_pack_start(GTK_BOX(vbox), input_box, FALSE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(input_box), 
			gtk_label_new("过滤端口："), FALSE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(input_box), entry_port, FALSE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(input_box), gtk_label_new("（Tip：留空负数为全部端口）"),
			FALSE, TRUE, 2);

	ip_datas.list = clist;
	ip_datas.entry1 = (GtkEntry*) entry_ip;
	ip_datas.entry2 = (GtkEntry*) entry_port;
	gtk_signal_connect(GTK_OBJECT(btn), "clicked", 
			GTK_SIGNAL_FUNC(filter_action_callback), "");
	// gtk_box_pack_start(GTK_BOX(container), vbox, TRUE, TRUE, 0);
	gtk_widget_show_all(vbox);
	return vbox;
}

/**
 * once to add the list item, use to reflash
 */
void refresh_list_datas(GtkWidget *list)
{
	if(!list)
	{
		return;
	}
	if(GTK_IS_CLIST(list))
	{
		gtk_clist_clear(GTK_CLIST(list));
		ip_link_t *head = get_ip_all();
		clist_add_datas(list, head, 9);
		free_ip_link(head);
		head = NULL;
	}
	else if(GTK_IS_LIST(list))
	{
		// FIXME:to remove all child of the container,and add it
		GList *children = NULL, *iter = NULL;
		children = gtk_container_get_children(GTK_CONTAINER(list));
		for(iter = children; iter != NULL; iter = g_list_next(iter))
		{
			gtk_widget_destroy(GTK_WIDGET(iter->data));
		}
		g_list_free(children);
		init_addr_translate(list);
	}
}

/**
 * add item to clist
 * @Deprecated: use the flush_clist() instead
 */
void add_clist_item(const gchar *src, const gchar *src_port, char *proto)
{
	int i = 0;
	// the item insert to clist
	gchar **text = (gchar**)malloc(sizeof(gchar*) * 9);
	for(i = 0; i < 9; ++i)
	{
		text[i] = (gchar*) malloc(sizeof(gchar) * 19);
		bzero(text[i], sizeof(gchar) * 19);
	}

	strcpy(text[0], src);
	strcpy(text[1], atoi(src_port) > 0? src_port : "all");
	strcpy(text[2], "0.0.0.0");
	strcpy(text[3], "all");
	strcpy(text[4], proto);
	strcpy(text[5], "DROP");
	strcpy(text[6], "filter");
	strcpy(text[7], "INPUT");
	strcpy(text[8], "0");
	gtk_clist_prepend(GTK_CLIST(ip_datas.list), text); 

	for(i = 0; i < 9; ++i)
	{
		free(text[i]);
	}
	free(text);

}

/** ip filter action callback */
void filter_action_callback(GtkWidget *widget, gpointer p)
{
	static gchar *toggle_udp = NULL;
	static gchar *toggle_tcp = NULL;
	static gchar *toggle_icmp = NULL;
	static gchar *toggle_all = NULL;

	if(!p)
	{
		const gchar *name = gtk_button_get_label((GtkButton*)widget);
		if(!strcmp(name, "ALL PROTO"))
		{
			toggle_all = gtk_toggle_button_get_active((GtkToggleButton*)widget)? 
				"all" : NULL;
		}

		if(!strcmp(name, "TCP"))
		{
			toggle_tcp = gtk_toggle_button_get_active((GtkToggleButton*)widget)? 
				"tcp" : NULL;
		}

		if(!strcmp(name, "UDP"))
		{
			toggle_udp = gtk_toggle_button_get_active((GtkToggleButton*)widget)? 
				"udp" : NULL;
		}

		if(!strcmp(name, "ICMP"))
		{
			toggle_icmp = gtk_toggle_button_get_active((GtkToggleButton*)widget)? 
				"icmp" : NULL;
		}
		return;
	}

	if(!toggle_udp && !toggle_tcp && !toggle_icmp && !toggle_all)
	{
		return;
	}

	// struct addr_entry *entrys = (struct addr_entry*) p;
	const gchar *ip = gtk_entry_get_text(ip_datas.entry1);
	const gchar *port = gtk_entry_get_text(ip_datas.entry2);
	int flag = 0;
	if(!strcmp(ip, ""))
	{
		g_print(">>> ip empty\n");
		return;
	}
	g_print("%s:%s\n", ip, port);
	// use insert and add head to clist
	if(toggle_all)
	{
		// if there are port, some limit must be effect
		if(strcmp(port, ""))
		{
			flag = add_rule(FILTER_TABLE, INPUT_CHAIN, NULL, 0, 
					(char*)ip, atoi(port), "0.0.0.0", -1, ACTION_DROP, F_HEAD);
		}
		else 
		{
			flag = add_rule2(FILTER_TABLE, INPUT_CHAIN, NULL, 
					0, (char*)ip, NULL, ACTION_DROP, F_HEAD);
		}
	}

	if(toggle_tcp && !toggle_all)
	{
		if(strcmp(port, ""))
		{
			flag = add_rule(FILTER_TABLE, INPUT_CHAIN, NULL, IPPROTO_TCP, 
					(char*)ip, atoi(port), "0.0.0.0", -1, ACTION_DROP, F_HEAD);
		}
		else 
		{
			flag = add_rule2(FILTER_TABLE, INPUT_CHAIN, NULL, 
					IPPROTO_TCP, (char*)ip, NULL, ACTION_DROP, F_HEAD);
		}
	}
	if(toggle_udp && !toggle_all)
	{
		if(strcmp(port, ""))
		{
			flag = add_rule(FILTER_TABLE, INPUT_CHAIN, NULL, IPPROTO_UDP,
					(char*)ip, atoi(port), "0.0.0.0", -1, ACTION_DROP, F_HEAD);
		}
		else 
		{
			flag = add_rule2(FILTER_TABLE, INPUT_CHAIN, NULL, 
					IPPROTO_UDP, (char*)ip, NULL, ACTION_DROP, F_HEAD);
		}

	}
	if(toggle_icmp && !toggle_all)
	{
		if(strcmp(port, ""))
		{
			flag = add_rule(FILTER_TABLE, INPUT_CHAIN, NULL, IPPROTO_ICMP,
					(char*)ip, atoi(port), "0.0.0.0", -1, ACTION_DROP, F_HEAD);
		}
		else
		{
			flag = add_rule2(FILTER_TABLE, INPUT_CHAIN, NULL,
					IPPROTO_ICMP, (char*)ip, NULL, ACTION_DROP, F_HEAD);
		}
	}

	if(flag)
	{
		// TODO create the dialog to show true
		refresh_list_datas(ip_datas.list);
	}
}

/** create the clist */
GtkWidget* create_clist(gchar **titles, gint column)
{
	GtkWidget *clist;
	gint i;

	if(!titles)
	{
		return NULL;
	}

	clist = gtk_clist_new_with_titles(column, titles);
	for(i = 0; i < column; ++i)
	{
		gtk_clist_set_column_width(GTK_CLIST(clist), i, 80);
	}

	return clist;
}

/** clist add datas */
void clist_add_datas(GtkWidget *clist, ip_link_t *head, gint column)
{
	gint size = 0;
	gint i;
	gint j;
	ip_link_t *link = head;
	gchar **text = NULL;

	if(!head || !clist)
	{
		return;
	}

	while(link)
	{
		// calculate the size
		++ size;
		link = link->next;
	}

	link = head;
	for(i = 0; i < size; ++i)
	{
		text = (gchar**) malloc(sizeof(gchar*) * column);
		gint item_size = 0;
		item_size = sizeof(gchar) * strlen(link->ip.src_ip) + 1;
		text[0] = (gchar*) malloc(item_size);
		bzero(text[0], item_size);
		strcpy(text[0], link->ip.src_ip);

		item_size = sizeof(gchar) * strlen(link->ip.src_port) + 1;
		text[1] = (gchar*) malloc(item_size);
		bzero(text[1], item_size);
		strcpy(text[1], link->ip.src_port);

		item_size = sizeof(gchar) * strlen(link->ip.dst_ip) + 1;
		text[2] = (gchar*) malloc(item_size);
		bzero(text[2], item_size);
		strcpy(text[2], link->ip.dst_ip);

		item_size = sizeof(gchar) * strlen(link->ip.dst_port) + 1;
		text[3] = (gchar*) malloc(item_size);
		bzero(text[3], item_size);
		strcpy(text[3], link->ip.dst_port);

		char *prot = NULL;
		struct protoent *p = getprotobynumber(link->ip.proto);
		if(p)
		{
			prot = p->p_name;
		}
		else 
		{
			prot = "other";
		}
		item_size = sizeof(gchar) * strlen(prot) + 1;
		text[4] = (gchar*) malloc(item_size);
		bzero(text[4], item_size);
		strcpy(text[4], prot);

		item_size = sizeof(gchar) * strlen(link->ip.action) + 1;
		text[5] = (gchar*) malloc(item_size);
		bzero(text[5], item_size);
		strcpy(text[5], link->ip.action);

		// like filter:FORWARD
		item_size = sizeof(gchar) * strlen(link->ip.table) + 1;
		text[6] = (gchar*) malloc(item_size);
		bzero(text[6], item_size);
		strcpy(text[6], link->ip.table);

		item_size = sizeof(gchar) * strlen(link->ip.chain) + 1;
		text[7] = (gchar*) malloc(item_size);
		bzero(text[7], item_size);
		strcpy(text[7], link->ip.chain);

		item_size = sizeof(gchar) * 10;
		text[8] = (gchar*) malloc(item_size);
		bzero(text[8], item_size);
		sprintf(text[8], "%d", link->ip.index);

		// add to the clist
		gtk_clist_append(GTK_CLIST(clist), text);
		for(j = 0; j < column; ++j)
		{
			free(text[j]);
			text[j] = NULL;
		}
		free(text);
		text = NULL;
		link = link->next;
	}
}

/** view to show the network track */
GtkWidget* show_network_track(GtkWidget *container)
{
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *list;
	GtkWidget *start_btn;
	GtkWidget *stop_btn;
	GtkWidget *scroller;

	vbox = gtk_vbox_new(FALSE, 0);
	scroller = gtk_scrolled_window_new(NULL,
			GTK_ADJUSTMENT(gtk_adjustment_new(0, 0, 0, 0, 0, 0)));
	list = gtk_list_new();
	gtk_scrolled_window_add_with_viewport(
			GTK_SCROLLED_WINDOW(scroller), list);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
	gtk_box_pack_start(GTK_BOX(vbox), scroller, TRUE, TRUE, 0);
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_end(GTK_BOX(vbox), hbox, FALSE, TRUE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 8);
	start_btn = gtk_button_new_with_label("开始");
	stop_btn = gtk_button_new_with_label("停止");
	gtk_signal_connect(GTK_OBJECT(start_btn), "clicked", 
			GTK_SIGNAL_FUNC(start_track), list);
	gtk_signal_connect(GTK_OBJECT(stop_btn), "clicked", 
			GTK_SIGNAL_FUNC(stop_track), list);
	gtk_box_pack_end(GTK_BOX(hbox), start_btn, FALSE, TRUE, 0);
	gtk_box_pack_end(GTK_BOX(hbox), stop_btn, FALSE, TRUE, 5);
	gtk_widget_show_all(vbox);
	return vbox;
}

/** get current network translate datas */
void p_get_netcap(void *p)
{
	const char *d = device;
	gchar text[200] = {'\0'};
	netcap_t info;
	p_flag = cap_init(d);

	while(p_flag)
	{
		bzero(&info, sizeof(info));
		get_netcap(&info);
		sprintf(text, "源地址:  %s,  目标地址:  %s, 协议: %s,  数据包长度: %d", 
				info.src_ip, info.dst_ip, info.proto, info.len);
		gdk_threads_enter();
		GtkWidget *label = gtk_list_item_new_with_label(text);
		gtk_container_add(GTK_CONTAINER(p), label);
		gtk_widget_show(label);
		gdk_threads_leave();
	}   
	cap_close();
	p_flag = 0;
	return;
}

void start_track(GtkWidget *widget, gpointer p)
{
	if(p_flag)
	{
		return;
	}
	// can not use the linux thread to update the view
	/*
	   if(pthread_create(&tid, NULL, p_get_netcap, p))
	   {
	   perror("pthread_create error");
	   return;
	   }
	   pthread_join(tid, NULL);*/
	gdk_threads_init();
	g_thread_create((GThreadFunc)p_get_netcap, p, FALSE, NULL); 
}

void stop_track(GtkWidget *widget, gpointer p)
{
	if(!p_flag)
	{
		return;
	}
	p_flag = 0;
}

/** first to init the network translate list datas*/
void init_addr_translate(GtkWidget *list)
{
	char *default_ip = "0.0.0.0";
	char text[100] = {'\0'};
	char name[50] = {'\0'};
	ip_link_t *head = get_ip_by_table("nat");
	struct protoent *p;
	ip_link_t *t = head;
	char *proto = NULL;
	GtkWidget *widget;

	while(t)
	{
		bzero(text, sizeof(char) * 100);
		bzero(name, sizeof(char) * 50);
		p = getprotobynumber(t->ip.proto);
		if(p) proto = p->p_name;
		else proto = "other";
		sprintf(text, "%s %s %s --> %s %s to %s-%s",
				t->ip.action, proto, 
				t->ip.src_ip? t->ip.src_ip : default_ip, 
				t->ip.dst_ip? t->ip.dst_ip : default_ip,
				proto, 
				t->ip.nat_minip? t->ip.nat_minip : default_ip,
				t->ip.nat_maxip? t->ip.nat_maxip : default_ip);
		sprintf(name, "%s:%s:%d", t->ip.table, t->ip.chain, t->ip.index);
		t = t->next;
		widget = gtk_list_item_new_with_label(text);
		gtk_widget_set_name(GTK_WIDGET(widget), name);
		gtk_signal_connect(GTK_OBJECT(widget),
				"button_press_event",
				GTK_SIGNAL_FUNC(rm_list_item_callback),
				list);
		gtk_container_add(GTK_CONTAINER(list), widget);
		gtk_widget_show(widget);
	}
	free_ip_link(head);
	head = NULL;
}

/** view to show the addr_translate */
GtkWidget *show_addr_translate(GtkWidget *container)
{
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *btn;
	GtkWidget *list;
	GtkWidget *scroller;
	GtkWidget *src_ip;
	GtkWidget *dst_ip;
	GtkWidget *min_ip;
	GtkWidget *max_ip;

	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);

	hbox = gtk_hbox_new(FALSE, 0);
	src_ip = gtk_entry_new_with_max_length(15);
	dst_ip = gtk_entry_new_with_max_length(15);
	min_ip = gtk_entry_new_with_max_length(15);
	max_ip = gtk_entry_new_with_max_length(15);
	gtk_box_pack_start(GTK_BOX(hbox), gtk_label_new("源地IP："), 
			FALSE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), src_ip, FALSE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), gtk_label_new("目的IP："), 
			FALSE, TRUE, 5);
	gtk_box_pack_start(GTK_BOX(hbox), dst_ip, FALSE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, TRUE, 0);
	btn = gtk_check_button_new_with_label("TCP");
	gtk_box_pack_start(GTK_BOX(hbox), btn, FALSE, TRUE, 0);
	gtk_signal_connect(GTK_OBJECT(btn), "toggled", 
			GTK_SIGNAL_FUNC(net_action_callback), "TCP");
	btn = gtk_check_button_new_with_label("UDP");
	gtk_box_pack_start(GTK_BOX(hbox), btn, FALSE, TRUE, 5);
	gtk_signal_connect(GTK_OBJECT(btn), "toggled", 
			GTK_SIGNAL_FUNC(net_action_callback), "UDP");

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), gtk_label_new("开始IP："),
			FALSE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), min_ip, FALSE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), gtk_label_new("结束IP："),
			FALSE, TRUE, 5);
	gtk_box_pack_start(GTK_BOX(hbox), max_ip, TRUE, TRUE, 0);
	btn = gtk_button_new_with_label("添加");
	gtk_box_pack_end(GTK_BOX(hbox), btn, FALSE, TRUE, 5);
	gtk_signal_connect(GTK_OBJECT(btn), "clicked", 
			GTK_SIGNAL_FUNC(net_action_callback), NULL);
	btn = gtk_check_button_new_with_label("DNAT");
	gtk_box_pack_end(GTK_BOX(hbox), btn, FALSE, TRUE, 5);
	gtk_signal_connect(GTK_OBJECT(btn), "toggled", 
			GTK_SIGNAL_FUNC(net_action_callback), "DNAT");
	btn = gtk_check_button_new_with_label("SNAT");
	gtk_box_pack_end(GTK_BOX(hbox), btn, FALSE, TRUE, 0);
	gtk_signal_connect(GTK_OBJECT(btn), "toggled", 
			GTK_SIGNAL_FUNC(net_action_callback), "SNAT");
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, TRUE, 5);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, TRUE, 0);

	list = gtk_list_new();
	scroller = gtk_scrolled_window_new(NULL,
			GTK_ADJUSTMENT(gtk_adjustment_new(0, 0, 0, 0, 0, 0)));
	gtk_scrolled_window_add_with_viewport(
			GTK_SCROLLED_WINDOW(scroller), list);
	gtk_box_pack_start(GTK_BOX(vbox), scroller, TRUE, TRUE, 8);
	init_addr_translate(list);
	gtk_widget_show_all(vbox);

	ip_datas.list = list;
	ip_datas.entry1 = (GtkEntry*) src_ip;
	ip_datas.entry2 = (GtkEntry*) dst_ip;
	ip_datas.entry3 = (GtkEntry*) min_ip;
	ip_datas.entry4 = (GtkEntry*) max_ip;

	return vbox;
}

void net_action_callback(GtkWidget *widget, gpointer p)
{
	static const char *default_ip = "0.0.0.0";
	static char *src_ip = NULL;
	static char *dst_ip = NULL;
	static char *min_ip = NULL;
	static char *max_ip = NULL;
	static char *tcp = NULL;
	static char *udp = NULL;
	static char *snat = NULL;
	static char *dnat = NULL;
	char *name = (char*)p;
	// to record the check button
	int flag = 0;
	if(name)
	{
		if(!strcmp(name, "SNAT"))
		{
			snat = gtk_toggle_button_get_active((GtkToggleButton*)widget)? 
				"snat" : NULL;
		}
		if(!strcmp(name, "DNAT"))
		{
			dnat = gtk_toggle_button_get_active((GtkToggleButton*)widget)?
				"dnat" : NULL;
		}
		if(!strcmp(name, "TCP"))
		{
			tcp = gtk_toggle_button_get_active((GtkToggleButton*)widget)? 
				"tcp" : NULL;
		}
		if(!strcmp(name, "UDP"))
		{
			udp = gtk_toggle_button_get_active((GtkToggleButton*)widget)? 
				"udp" : NULL;
		}
		return;
	}
	// process the add btn, to add the rule
	src_ip = (char*) gtk_entry_get_text(ip_datas.entry1);
	dst_ip = (char*) gtk_entry_get_text(ip_datas.entry2);
	min_ip = (char*) gtk_entry_get_text(ip_datas.entry3);
	max_ip = (char*) gtk_entry_get_text(ip_datas.entry4);

	if(!strcmp(min_ip, "")) min_ip = NULL;
	if(!strcmp(max_ip, "")) max_ip = NULL;
	if(!strcmp(src_ip, "")) src_ip = NULL;
	if(!strcmp(dst_ip, "")) dst_ip = NULL;

	if((!min_ip && !max_ip) || (!src_ip && !dst_ip)
			|| (!udp && !tcp))
	{
		g_print(">>> nat add, there must be encough info\n");
		return;
	}

	// FIXME: to many logic
	// NOTE: -1 is all port
	if(snat && tcp && add_nat_rule(PRE_ROUTING_CHAIN, NULL, IPPROTO_TCP, 
				src_ip, -1, dst_ip, -1, 
				min_ip, -1, max_ip, -1, ACTION_SNAT, F_HEAD))
	{
		flag = 1;
	}
	if(udp && add_nat_rule(PRE_ROUTING_CHAIN, NULL, IPPROTO_UDP, 
				src_ip, -1, dst_ip, -1, 
				min_ip, -1, max_ip, -1, ACTION_SNAT, F_HEAD))
	{
		flag = 1;
	}

	// NOTE: -1 is all port
	if(dnat && tcp && add_nat_rule(PRE_ROUTING_CHAIN, NULL, IPPROTO_TCP, 
				src_ip, -1, dst_ip, -1, 
				min_ip, -1, max_ip, -1, ACTION_DNAT, F_HEAD))
	{
		flag = 1;
	}
	if(dnat && udp && add_nat_rule(PRE_ROUTING_CHAIN, NULL, IPPROTO_UDP, 
				src_ip, -1, dst_ip, -1, 
				min_ip, -1, max_ip, -1, ACTION_DNAT, F_HEAD))
	{
		flag = 1;
	}

	// list data change, to refresh the list datas
	if(flag)
	{
		refresh_list_datas(ip_datas.list);
	}
}

/** for list double click */
gboolean rm_list_item_callback(GtkWidget *widget,
		GdkEvent *event, gpointer data)
{
	GtkWidget *ok_btn = NULL;
	GtkWidget *cancel_btn = NULL;
	bzero(&delete_rule, sizeof(delete_rule));
	if (GTK_IS_LIST_ITEM(widget) &&
			(event->type==GDK_2BUTTON_PRESS ||
			 event->type==GDK_3BUTTON_PRESS) )
	{
		char str[30] = {'\0'};
		gtk_widget_get_name(widget);
		strcpy(str, (char *)gtk_widget_get_name(widget));
		// the widget name string is 'table':'chain':'index'
		char *p = strtok(str, ":");
		strcpy(delete_rule.table_name, p);
		p = strtok(NULL, ":");
		strcpy(delete_rule.chain_name, p);
		p = strtok(NULL, ":");
		delete_rule.index = atoi(p);
	}
	else if(event->type == GDK_2BUTTON_PRESS 
			|| event->type == GDK_3BUTTON_PRESS)
	{
		gchar *msg = NULL;
		// if there are no any items
		if(GTK_CLIST(widget)->focus_row == -1)
		{
			return FALSE;
		}

		gtk_clist_get_text (GTK_CLIST(widget), GTK_CLIST(widget)->focus_row , 8, &msg);
		delete_rule.index = atoi(msg);
		gtk_clist_get_text (GTK_CLIST(widget), GTK_CLIST(widget)->focus_row , 7, &msg);
		strcpy(delete_rule.chain_name, msg);
		gtk_clist_get_text (GTK_CLIST(widget), GTK_CLIST(widget)->focus_row , 6, &msg);
		strcpy(delete_rule.table_name, msg);
	}
	else 
	{
		return FALSE;
	}
	create_dialog("提示", "确定要删除这条记录吗？", 
			TRUE, TRUE, &ok_btn, &cancel_btn);
	return FALSE;
}

void init_views(int argc, char** argv, 
		char *statusbar_text, char *d)
{
	GtkWidget *win;
	GtkWidget *menubar;
	GtkWidget *statusbar;
	GtkWidget *toolbar;
	GtkWidget *box;
	GtkWidget *frame;

	// g_thread_init(NULL);
	gtk_init(&argc, &argv);

	win = create_win();
	frame = gtk_frame_new("工具");
	menubar = create_menu(win);
	toolbar = create_toolbar();
	statusbar = create_statusbar();
	box = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(win), box);
	gtk_container_add(GTK_CONTAINER(frame), toolbar);
	gtk_container_set_border_width(GTK_CONTAINER(frame), 8);
	gtk_box_pack_start(GTK_BOX(box), menubar, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(box), statusbar, FALSE, FALSE, 0);
	show_content = show_ip_filter(box);
	ipfilter_widget = show_content;
	main_container = box;
	set_statusbar_text(statusbar, statusbar_text);
	device = d;
	gtk_box_pack_start(GTK_BOX(box), show_content, TRUE, TRUE, 0);
	gtk_widget_show_all(win);

	gtk_main();
}
