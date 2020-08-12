#include <stdlib.h>

#include "minitalk.c"
#include "loop.c"

extern t_ncu ncu;
char readBuffer[256];

void read_in(){
		int					j = 0;
		int					len = 0;
		int					ch;

		wmove(ncu.textWin, 0, 0);
		wrefresh(ncu.textWin);
		while ((ch = getch()) != '\n')
		{
			// Backspace
			if (ch == KEY_BACKSPACE) {
				if (j > 0) {
					wmove(ncu.textWin, 0, --j);
					wdelch(ncu.textWin);
					strncpy(readBuffer + j, readBuffer + j + 1, len - j);
					len--;
					wrefresh(ncu.textWin);
				}
			}
			else if (ch == KEY_DC) {
				if (j < len) {
					wdelch(ncu.textWin);
					strncpy(readBuffer + j, readBuffer + j + 1, len - j);
					len--;
					wrefresh(ncu.textWin);
				}
			}
			else if (ch == KEY_LEFT) {
				if (j > 0) {
					wmove(ncu.textWin, 0, --j);
					wrefresh(ncu.textWin);
				}
			}
			else if (ch == KEY_RIGHT) {
				if (j < len) {
					wmove(ncu.textWin, 0, ++j);
					wrefresh(ncu.textWin);
				}
			}
			else if (ch != ERR && ch >= 32 && ch <= 126) {
				if (j < 256 - 1) {
					if (j < len) {
						strncpy(readBuffer + j + 1, readBuffer + j, len - j);
						winsch(ncu.textWin, ch);
						wmove(ncu.textWin, 0, j + 1);
					}
					else {
						wprintw(ncu.textWin, "%c", ch);
					}
					readBuffer[j++] = ch;
					len++;
					wrefresh(ncu.textWin);
				}
				else {
					readBuffer[--j] = '\0';
					readBuffer[j - 1] = ch;
					wprintw(ncu.textWin, "\b%c", ch);
					wrefresh(ncu.textWin);
				}
			}
		}
		readBuffer[len] = '\0';
		wprintw(ncu.tchatWin, "%s\n", readBuffer);
		wrefresh(ncu.tchatWin);
		wrefresh(ncu.tchatWin);
		wclear(ncu.textWin);
		wrefresh(ncu.textWin);
}

int main(){
	ncurses_start();
	//wprintw(ncu.tchatWin, "%\n", BUF_CLIENTS);
	while(1){
		read_in();
		
	}
	getch();
	ncurses_end();
	return 0;
}
