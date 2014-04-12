# The folder of the source
src_folder = src
bin_folder = bin

all: $(src_folder)/main.c $(src_folder)/common_tools.c \
	$(src_folder)/netfilter_utils.c $(src_folder)/gtk_win_view.c
	gcc -g -o $(bin_folder)/main.o $(src_folder)/main.c $(src_folder)/common_tools.c \
		$(src_folder)/netfilter_utils.c $(src_folder)/gtk_win_view.c \
	`pkg-config --libs --cflags gtk+-2.0 gthread-2.0` -lip4tc -lpcap

clean:
	rm -rf $(bin_folder)/*.o
