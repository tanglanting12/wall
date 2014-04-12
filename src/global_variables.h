#ifndef _GLOBAL_VARIABLE_
#define _GLOBAL_VARIABLE_

/** toolbar item names */
static char *TITLES[] = {
	"IP过滤", "网络追踪", "地址转换", "关于软件"
};

/** icon paths */
static char *APP_ICON_PATH = "../image/ic_firewall.png";
static char *IMAGE_PATHS[] = {
	"../image/ic_filter_settings.png",
	"../image/ic_network_track.png",
	"../image/ic_transfer.png",
	"../image/ic_about.png"
};

/** the main win name */
static char *APP_NAME = "MINI Firewall";
static char *WIN_NAME = "MINI Firewall -- Design by 林浩杰";

/** the toolbar item sizes */
static int SIZE = 4;

/** the main win size */
static int WIN_WIDTH = 640;
static int WIN_HEIGHT = 480;

#endif
