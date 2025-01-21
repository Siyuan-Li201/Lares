import pandas as pd
import numpy as np


class FSM:
    """
    有限状态自动机
    ------------
    输入:
      delta: 状态转移矩阵, 要求是一个 DataFrame 对象
      init: 初态集, 要求是一个列表
      final: 终态集, 要求是一个列表

    支持:
      1. 状态的转换与 token 的匹配
      2. 非确定有限状态自动机的确定化
      3. 确定的有限状态自动机最小化
    """
    def __init__(self, delta: pd.DataFrame, init: list, final: list):
        self.delta = delta  # 状态转换矩阵
        self.init = init    # 初态集
        self.final = final  # 终态集


    def forward(self, cstate, chr):
        """通过查找状态转换矩阵的值进行状态的转换"""
        try:
            if (chr == '-' or chr == '>' or chr == '[' or chr == ']') and cstate == 2:
                return 2
            if (chr == '|' or chr == '&') and cstate == 0:
                return 2
            if chr == 'x' and cstate == 4:
                return 4
            return self.delta[chr][cstate]
        except:
            return 2
            print("错误: 状态转换失败")

    
    def isnfa(self):
        """判断是否为非确定有限状态自动机"""
        return '' in self.delta.columns
    

    def isdfa(self):
        """判断是否为确定有限状态自动机"""
        return '' not in self.delta.columns


    def move(self, state_set, chr):
        """计算从状态集合中的某一状态经过一条chr弧而到达的状态全体"""
        next_set = []
        for state in state_set:
            next = self.forward(state, chr)
            if not pd.isnull(next):
                if not isinstance(next, list):
                    next = [next]
                next_set += next
        return next_set


    def epsilon_closure(self, state_set):
        """计算状态集合的ε-闭包"""
        closure = state_set.copy()
        for state in state_set:
            epsilon_next = self.forward(state, '')

            if not isinstance(epsilon_next, list):
                epsilon_next = [epsilon_next]
            else:
                epsilon_next = epsilon_next.copy()
            closure += epsilon_next
            if state in epsilon_next:
                epsilon_next.remove(state)

            closure += self.epsilon_closure(epsilon_next)
        return list(set(closure))


    def nfa2dfa(self):
        """将非确定有限状态自动机确定化, 转换为确定有限状态自动机"""
        if self.isdfa():
            print("错误: 该有限状态自动机已经是确定化状态, 不可重复确定化")
            return

        dfa_states = []
        dfa_states.append(self.epsilon_closure([0]))
        state_queue = dfa_states.copy()

        dfa_delta = []
        while True:
            if not state_queue:
                break
            cstate = state_queue[0]
            state_queue.pop(0)
            delta_item = {}

            for chr in self.delta.columns:
                if chr == '':
                    continue
                nstate = self.epsilon_closure(self.move(cstate, chr))
                if nstate not in dfa_states:
                    dfa_states.append(nstate)
                    state_queue.append(nstate)
                delta_item.update({chr: dfa_states.index(nstate)})

            dfa_delta.append(delta_item)
        self.delta = pd.DataFrame(dfa_delta)

        # 更新初态集和终态集
        dfa_init = []
        dfa_final = []
        for state in dfa_states:
            for init_state in self.init:
                if init_state in state:
                    dfa_init.append(dfa_states.index(state))
            for final_state in self.final:
                if final_state in state:
                    dfa_final.append(dfa_states.index(state))
        self.init = list(set(dfa_init))
        self.final = list(set(dfa_final))


    def minimize_dfa(self):
        """化简确定有限状态自动机, 使之最小化"""
        if self.isnfa():
            print("错误: 该有限状态自动机还未确定化, 请先将其确定化")
            return
        
        # 步骤0: 检查是否为全状态的有限状态自动机, 如果不是则需要添加死状态
        if self.delta.isnull().sum().sum() > 0:
            dead_state = len(self.delta.index)
            self.delta.loc[dead_state] = [dead_state for _ in self.delta.columns]
            self.delta = self.delta.applymap(lambda x: dead_state if pd.isnull(x) else x)

        # 步骤1: 初始化分: 构造终态和非终态两组划分
        nofinal = [state if state not in self.final else np.nan for state in self.delta.index]
        nofinal = list(filter(lambda x: not pd.isnull(x), nofinal))
        partition = [nofinal, self.final]

        # 步骤2: 使用传播性原则构造新的划分, 直到不能再继续划分为止
        while True:
            partition_ = partition.copy()
            for iset in partition:
                cut = False
                for chr in self.delta.columns:
                    nset = set(self.move(iset, chr))

                    cut = True
                    for jset in partition:
                        if nset <= set(jset):
                            # 状态集合经过一条chr弧到达的状态全体包含于原划分的某个状态组, 不用继续划分
                            cut = False
                            break
                    if cut:
                        # 状态集合经过一条chr弧到达的状态全体不全包含于原划分的某个状态组, 则需要继续划分
                        iset_dir = {}
                        for state in iset:
                            nstate = self.forward(state, chr)
                            for jset in partition:
                                if nstate in jset:
                                    break
                            if tuple(jset) not in iset_dir:
                                iset_dir[tuple(jset)] = []
                            iset_dir[tuple(jset)].append(state)
                        update = list(iset_dir.values())
                        partition.remove(iset)
                        partition += update
                        break
                if cut:
                    break
            if partition_ == partition:
                break

        # 步骤3: 为最终划分的每一组选择一个代表, 这里我们选择每一组的第一个状态作为代表
        dfa_delta = []
        dfa_init = []
        dfa_final = []

        for iset in partition:
            delta_item = {}
            for chr in self.delta.columns:
                nstate = self.forward(iset[0], chr)
                # 检查 nstate 包含于划分中的哪一组
                for jset in partition:
                    if nstate in jset:
                        delta_item.update({chr: partition.index(jset)})
                        break
            dfa_delta.append(delta_item)

            for state in iset:
                if state in self.init:
                    dfa_init.append(partition.index(iset))
                if state in self.final:
                    dfa_final.append(partition.index(iset))

        self.delta = pd.DataFrame(dfa_delta)
        self.init = list(set(dfa_init))
        self.final = list(set(dfa_final))

        # 步骤4: 去掉新得到有限状态自动机中的死状态
        dead_states = []
        for state in self.delta.index:
            # 死状态的判定: 没有通路到达终态的状态是死状态
            if state in (dead_states + self.final):
                continue
            chr_idx = 0
            cstate = state
            trigger = False
            while True:
                # 尝试找到一条到达终态的通路
                nstate = self.forward(cstate, self.delta.columns[chr_idx])
                if nstate in self.final:
                    # 已到达终态
                    break
                if pd.isnull(nstate) or nstate == cstate:
                    # 此路不通, 尝试其它路径
                    if chr_idx < len(self.delta.columns) - 1:
                        chr_idx += 1
                        trigger = True
                    else:
                        # 找到一个死状态, 去除之
                        self.delta = self.delta.drop(index=cstate)
                        self.delta = self.delta.applymap(lambda x: np.nan if x == cstate else x)
                        dead_states.append(cstate)
                        break
                else:
                    if trigger:
                        trigger = False
                        chr_idx = 0
                    cstate = nstate
        

    def mathch(self, token):
        """输入一个字符串进行匹配, 若匹配成功则返回一个终态, 否则打印错误信息"""
        if self.isnfa():
            print("错误: 该有限状态自动机还未确定化, 请先将其确定化")
            return

        cstate = self.init[0]
        for chr in token:
            nstate = self.forward(cstate, chr)
            if pd.isnull(nstate):
                # print("错误: token 非法")
                if "0x" in token:
                    return 5
                else:
                    return 2
            cstate = nstate
        
        if cstate not in self.final:
            print("错误: token 不完整")
            return
        else:
            return cstate 
