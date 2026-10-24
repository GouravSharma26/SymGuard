# Classes and custom object method dispatch are deliberately not modeled
import os

class Sanitizer:
    def sanitize(self, text):
        return "clean"

s = Sanitizer()
cmd = s.sanitize(input())
os.system(cmd)
