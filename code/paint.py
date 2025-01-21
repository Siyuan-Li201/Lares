import matplotlib.pyplot as plt
import numpy as np
import matplotlib.patheffects as path_effects

# 设置字体样式
plt.style.use('seaborn-v0_8')
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['Arial']

# 数据
models = ['BinXray', 'Robin', 'PS3', 'Lares']
offline = [18.4, 472, 45, 20.3]
online = [10.2, 17.31, 19.52, 15.6]
all_time = [28.6, 489.31, 64.52, 35.9]

# 设置更柔和的颜色
colors = ['#5DA5DA', '#FAA43A', '#60BD68']

# 设置柱状图的宽度和位置
x = np.arange(len(models))
bar_width = 0.25

# 创建图形和子图
fig, (ax1, ax2) = plt.subplots(2, 1, sharex=True, figsize=(12, 9), 
                              gridspec_kw={'height_ratios': [1, 2.5]})

# 绘制下半部分（0-100）
bars1 = ax2.bar(x - bar_width, offline, width=bar_width, label='Offline', 
                color=colors[0], edgecolor='white', linewidth=1.5)
bars2 = ax2.bar(x, online, width=bar_width, label='Online', 
                color=colors[1], edgecolor='white', linewidth=1.5)
bars3 = ax2.bar(x + bar_width, all_time, width=bar_width, label='All', 
                color=colors[2], edgecolor='white', linewidth=1.5)
ax2.set_ylim(0, 100)

# 绘制上半部分（400-500）
ax1.bar(x - bar_width, offline, width=bar_width, color=colors[0], 
        edgecolor='white', linewidth=1.5)
ax1.bar(x, online, width=bar_width, color=colors[1], 
        edgecolor='white', linewidth=1.5)
ax1.bar(x + bar_width, all_time, width=bar_width, color=colors[2], 
        edgecolor='white', linewidth=1.5)
ax1.set_ylim(400, 500)

# 添加网格线
ax1.grid(True, linestyle='--', alpha=0.4, color='gray')
ax2.grid(True, linestyle='--', alpha=0.4, color='gray')

# 优化断轴效果
ax1.spines['bottom'].set_visible(False)
ax2.spines['top'].set_visible(False)
ax1.tick_params(axis='x', which='both', bottom=False)
ax2.tick_params(axis='x', which='both', top=False)

# 添加更精致的断裂效果
d = 0.01
kwargs = dict(transform=ax1.transAxes, color='gray', clip_on=False, linewidth=1.5)
ax1.plot((-d*2, +d*2), (-d, +d), **kwargs)
ax1.plot((1-d*2, 1+d*2), (-d, +d), **kwargs)
kwargs.update(transform=ax2.transAxes)
ax2.plot((-d*2, +d*2), (1-d, 1+d), **kwargs)
ax2.plot((1-d*2, 1+d*2), (1-d, 1+d), **kwargs)

# 优化标签和标题
ax2.set_xlabel('Models', fontsize=22, fontweight='bold')
ax1.set_ylabel('Time (seconds)', fontsize=22, fontweight='bold')
ax2.set_ylabel('Time (seconds)', fontsize=22, fontweight='bold')
# plt.suptitle('Model Time Cost Comparison', fontsize=20, fontweight='bold', y=0.98)

# 设置刻度标签
ax2.set_xticks(x)
ax2.set_xticklabels(models, fontsize=20, fontweight='bold')

# 设置y轴刻度标签的字体大小
ax1.tick_params(axis='y', labelsize=20)
ax2.tick_params(axis='y', labelsize=20)

# 添加数值标签
def add_value_labels(ax, bars):
    for bar in bars:
        height = bar.get_height()
        if height > 0:  # 只为非零值添加标签
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{height:.1f}',
                   ha='center', va='bottom', fontsize=16, fontweight='bold')

add_value_labels(ax1, bars1)
add_value_labels(ax1, bars2)
add_value_labels(ax1, bars3)
add_value_labels(ax2, bars1)
add_value_labels(ax2, bars2)
add_value_labels(ax2, bars3)

# 优化图例
legend = ax2.legend(loc='upper right', bbox_to_anchor=(1, 0.98), 
                   ncol=3, frameon=True, fontsize=18)
legend.get_frame().set_facecolor('white')
legend.get_frame().set_alpha(0.9)
legend.get_frame().set_linewidth(1)

# 为柱状图添加阴影效果
for ax in [ax1, ax2]:
    for container in ax.containers:
        for bar in container:
            bar.set_path_effects([path_effects.withSimplePatchShadow()])

# 调整布局，减小边距
plt.tight_layout(pad=0.5)  # 减小pad值
plt.subplots_adjust(
    top=0.95,        # 顶部边距
    bottom=0.08,     # 底部边距
    left=0.08,       # 左边距
    right=0.98,      # 右边距
    hspace=0.1       # 子图间距
)

# 显示图表
plt.show()