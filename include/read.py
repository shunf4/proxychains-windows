import sys
print(" ".join([("00" + (hex(b)[2:]))[-2:] for b in eval("b" + open(sys.argv[1], "r").read().replace("static const char g_RemoteFuncX64[] = ", "").replace(";", ""))]))
