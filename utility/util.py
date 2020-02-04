import os
import psutil

process = None

def up(n):
    return "\u001b[%dA" % n

def down(n):
    return "\u001b[%dB" % n

def right(n):
    return "\u001b[%dC" % n

def left(n):
    return "\u001b[%dD" % n

def hook_all_models(proj, package):
    for el in dir(package):
        if "MODEL" in el:
            model = getattr(package, el)
            proj.hook_symbol(el.replace("MODEL", ""), model())

def hook_all_internal(proj, package):
    for el in dir(package):
        if "MODEL" in el:
            model = getattr(package, el)
            proj.hook(model().get_addr(), model())

def insert_or_add(dict, key, value):
    if key in dict:
        dict[key] += value
    else:
        dict[key]  = value

def insert_or_max(dict, key, value):
    if key in dict:
        dict[key] = max(dict[key], value)
    else:
        dict[key] = value

def combine_histograms(h1, h2):
    """ merge h2 in h1 """
    for key in h2:
        insert_or_add(h1, key, h2[key])

def combine_histograms_max(h1, h2):
    """ merge h2 in h1 """
    for key in h2:
        insert_or_max(h1, key, h2[key])

def check_weakref(a):
    try:
        a.__str__()
        return True
    except:
        return False

def get_memory_usage():
    global process
    if not process:
        process = psutil.Process(os.getpid())
    return process.memory_info().rss // (1024 * 1024)  # MiB
