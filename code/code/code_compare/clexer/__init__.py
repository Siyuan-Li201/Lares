"""
词法分析器
--------
功能:
    输入C--语言的源代码, 输出识别出单词符号序列, 并填写符号表.

输出格式:
    [源代码中的单词符号][TAB]<[单词符号类型]>
    
符号类型:
    KW: 关键字
    OP: 运算符
    SE: 界符
    IDN: 标识符
    INT: 整形数
"""

from .fsm import FSM
from .scanner import scan
