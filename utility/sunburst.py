import numpy as np
import matplotlib.pyplot as plt

data_ranges = []
colormap = plt.get_cmap('viridis')
h_dict = dict()

def extract_values(nodes):
    ris = []
    for ndata, _, subnodes in nodes:
        ris.append(ndata)
        ris.extend(extract_values(subnodes))
    return ris

def calculate_hdict(values):
    s = set()
    for v in values:
        s.add(str(v))

    i = 0
    for v in s:
        h_dict[v] = i/len(s)
        i+=1

def h(ndata):
    return h_dict[str(ndata)]

def sunburst(nodes, total=np.pi * 2, offset=0, level=0, ax=None):
    ax = ax or plt.subplot(111, projection='polar')

    if level == 0 and len(nodes) == 1:
        calculate_hdict(extract_values(nodes))
        ndata, value, subnodes = nodes[0]
        ax.bar([0], [0.5], [np.pi * 2], color=colormap(h(ndata)))
        data_ranges.append((0, 2*np.pi, 0.5, 0, ndata))
        # print(data_ranges)
        sunburst(subnodes, total=value, level=level + 1, ax=ax)
    elif nodes:
        d = np.pi * 2 / total
        data = []
        widths = []
        colors = []
        local_offset = offset
        for ndata, value, subnodes in nodes:
            data.append(ndata)
            widths.append(value * d)
            colors.append(colormap(h(ndata)))
            sunburst(subnodes, total=total, offset=local_offset,
                     level=level + 1, ax=ax)
            local_offset += value
        values = np.cumsum([offset * d] + widths[:-1])
        heights = [1] * len(nodes)
        bottoms = np.zeros(len(nodes)) + level - 0.5
        rects = ax.bar(values, heights, widths, bottoms, linewidth=1, color=colors,
                       # align='edge')
                       edgecolor='white', align='edge')
        for begin, width, height, bottom, ndata in zip(values, widths, heights, bottoms, data):
            data_ranges.append((begin, width, height, bottom, ndata))

    if level == 0:
        ax.set_theta_direction(-1)
        ax.set_theta_zero_location('N')
        ax.set_axis_off()

def register_callbacks():
    fig = plt.gcf()
    txt = None

    def onclick(event):
        global txt
        rho = event.ydata
        if event.xdata >= 0:
            phi = event.xdata 
        else:
            phi = 2*np.pi - (-event.xdata)
        
        for begin, width, height, bottom, ndata in data_ranges:
            if phi >= begin and phi <= begin+width and rho >= bottom and rho <= bottom+height:
                print("BINGO!", str(ndata), event.dblclick)
                if not event.dblclick:
                    txt = plt.text(event.xdata, event.ydata, str(ndata), fontsize=8, backgroundcolor='white')
                    fig.canvas.draw()

    def offclick(event):
        global txt
        if txt != None:
            txt.remove()
            fig.canvas.draw()

    fig.canvas.mpl_connect('button_press_event', onclick)
    fig.canvas.mpl_connect('button_release_event', offclick) 


def compute_sunburst(data):
    sunburst(data)
    # plt.savefig('graphs/sunburst.png')
    register_callbacks()
    plt.show()

if __name__=="__main__":
    data = [
        ('/', 100, [
            ('home', 70, [
                ('Images', 40, []),
                ('Videos', 20, []),
                ('Documents', 5, []),
            ]),
            ('usr', 30, [
                ('src', 6, [
                    ('linux-headers', 4, []),
                    ('virtualbox', 1, []),

                ]),
                ('lib', 4, []),
                ('share', 2, []),
                ('bin', 1, []),
                ('local', 1, []),
                ('include', 1, []),
            ]),
        ]),
    ]

    compute_sunburst(data)
