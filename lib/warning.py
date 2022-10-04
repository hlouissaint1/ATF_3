#! /usr/bin/python
BLACK = 0
RED = 1
GREEN = 2
AMBER = 3
BLUE = 4
MAGENTA = 5
CYAN = 6
WHITE = 7
BOLD = '\033[1m'
__color = lambda fg, bg, s :'\x1b[%sm %s \x1b[0m' % ('7;%s;%s' % (30 + bg, 40 + fg) , s)

def cprint(fg, bg, s):
        print __color(fg, bg, s)

border = '*' * 10
border2 = '!' * 6

warning = '\t\t%s This iSensor is used EXCLUSIVELY for production ruleset testing %s' % (border, border)
warning1 = '\t\t%s     Use of this device for any other purpose is not allowed     %s' % (border, border)
warning2 = '\t\t%s  ANY CHANGE TO THE CONFIGURATION OF THIS DEVICE IS STRICTLY PROHIBITED  %s' % (border2, border2)

cprint(AMBER, BLACK, BOLD+warning)
cprint(AMBER, BLACK, BOLD+warning1)
cprint(RED, BLACK, BOLD+warning2)


