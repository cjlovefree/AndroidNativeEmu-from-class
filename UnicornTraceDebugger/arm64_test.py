# -*- coding: UTF-8 -*-
from unicorn import *
from unicorn.arm64_const import *
from UnicornTraceDebugger import udbg_arm64
import logging
import sys

#以下演示调试器在arm64 下的调用。

logging.basicConfig(stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s")
logger = logging.getLogger(__name__)

def hook_code(uc, address, size, user_data):
    print(f">>> Tracing instruction at 0x{address:x}, run size = 0x{size:x}")


def hook_memory(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    print(f">>> Memory err pc:0x{pc:x} address:0x{address:x}, size:0x{size:x}")


a1 = b'JCKEHKGKIPQAKIL'
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
dbg = udbg_arm64.UnicornDebugger(mu)

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
#mu.mem_write(image_base + 0x1EDB0, b"\xD9\x98\x00\x00")

# 设置 Hook
mu.hook_add(UC_HOOK_CODE, hook_code, None)
mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_memory, None)

# 设置需要 Run 的函数地址
func_start = image_base + 0x064F1A0# + 0x1
func_end = image_base + 0x064F268

try:
    mu.emu_start(func_start, func_end)
    x2 = mu.reg_read(UC_ARM64_REG_X2)
    result = mu.mem_read(x2, 16)
    print(result.hex())
except UcError as e:
    #print(f"UC run error {e}")
    list_tracks = dbg.get_tracks()
    for addr in list_tracks[-100:-1]:
        print (hex(addr - 0xcbc66000)) #这里0xcbc66000是模拟运行中模块的基地址
    print (e)



'''
if __name__ == "__main__":
    # execute only if run as a script
    get_zhucema("JCKEHKGKIPQAKIL")
'''
