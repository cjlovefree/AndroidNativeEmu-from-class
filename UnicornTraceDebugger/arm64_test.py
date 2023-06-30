# -*- coding: UTF-8 -*-
from unicorn import *
from unicorn.arm64_const import *
from UnicornTraceDebugger import udbg_arm64
import logging
import sys

logging.basicConfig(stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s")
logger = logging.getLogger(__name__)

def hook_code(uc, address, size, user_data):
    print(f">>> Tracing instruction at 0x{address:x}, run size = 0x{size:x}")
    
    


def hook_memory(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    print(f">>> Memory err pc:0x{pc:x} address:0x{address:x}, size:0x{size:x}")


# 定义钩子函数，用于跳过指定地址的指令
def skip_instruction(uc, address, size, user_data):
    # 指定要跳过的指令地址
    skip_address = 0x0064F1B8 #这里跳过strlen函数

    # 判断当前指令地址是否需要跳过
    if address == skip_address:
        # 跳过指令
        uc.reg_write(UC_ARM64_REG_PC, address + size)
        uc.reg_write(UC_ARM64_REG_W0,15) #写15是因为strlen实际执行的结果是15




a1 = b'JCKEHKGKIPQAKIL'
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
dbg = udbg_arm64.UnicornDebugger(mu)
#dbg.add_bpt(0x64f1b8)#添加调试断点

# 分配 so 内存
image_base = 0x0
#image_size = 0x10000 * 8
image_size = 0x1400000 #分配20MB的内存
mu.mem_map(image_base, image_size)
with open("libAstroApiSdk.so", "rb") as f:
    sofile = f.read()
    mu.mem_write(image_base, sofile)

# 分配 Stack 内存
stack_base = 0x3200000 #从50MB处开始放入栈，因为文件8MB多
stack_size = 0x10000 * 3
stack_top = stack_base + stack_size - 0x8
mu.mem_map(stack_base, stack_size)
mu.reg_write(UC_ARM64_REG_SP, stack_top)

# 分配数据内存
data_base = 0x5000000 #80MB开始写数据
data_size = 0x10000 * 3
mu.mem_map(data_base, data_size)
mu.mem_write(data_base, a1)

##把参数赋值给寄存器
mu.reg_write(UC_ARM64_REG_X1, data_base)
mu.reg_write(UC_ARM64_REG_X0, 0)#this指针用不到先直接赋值0
mu.reg_write(UC_ARM64_REG_X2, data_base+32) #用来存储处理后的数据

# 修复 Got 表
'''
这个got表的fix只能fix本so已经包含的自己写的函数,对于系统库函数strlen这些是fix不了的，这是因为系统库libc.so没有（自动/正确）布局在内存中,
只能另外自己手动实现这些函数的功能，把返回结果补到对应的寄存器里面。
'''
#mu.mem_write(image_base + 0x0889978, b"\x50\x38\x99\x00\x00\x00\x00\x00")


# 设置 Hook
mu.hook_add(UC_HOOK_CODE, hook_code, None)
mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_memory, None)
mu.hook_add(UC_HOOK_CODE, skip_instruction, None)


# 设置需要 Run 的函数地址
func_start = image_base + 0x064F1A0# + 0x1
func_end = image_base + 0x064F268

try:
    mu.emu_start(func_start, func_end)
    x2 = mu.reg_read(UC_ARM64_REG_X2)
    result = mu.mem_read(x2, 16)
    print(result.hex())
    print("加密码是："+result.decode('ascii'))


except UcError as e:
    #print(f"UC run error {e}")
    list_tracks = dbg.get_tracks()
    for addr in list_tracks[-100:-1]:
        print (hex(addr)) #这里0xcbc66000是模拟运行中模块的基地址
    print (e)
    


'''
if __name__ == "__main__":
    # execute only if run as a script
    get_zhucema("JCKEHKGKIPQAKIL")
'''
