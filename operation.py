
import time
import os, subprocess, threading, signal
from typing import Callable
from devices import Device
from conf import NWIPE_BIN_PATH, SUDO_PASSWD

class OperationResult:
    def __init__(self, code: int, status: bool, message: str):
        self.code = code
        self.status = status
        self.message = message
    def __str__(self):
        return '{'+f"code: {self.code}, status: {self.status}, message: {self.message}"+'}'
    def __repr__(self):
        return self.__str__()
    

class OperationFailedType:
    WAITING_RESULT = -2
    UNKNWON_ERROR = -1
    SUCCESS = 0
    NO_PASSWORD_PROVIDED = 1
    PASSWORD_INCORRECT = 2
    CANT_FOUND_NWIPE = 3





def __callback__print(process: threading.Thread, output: str, index: int):
    print(f"[{index}]输出：", output)

def __subthread_reading_worker(process: subprocess.Popen, callback: Callable[[subprocess.Popen, str, int], None]):
    index = 0
    while True:
        output = process.stdout.readline().decode()
        if output:
            callback(process, output, index)
        else:
            break
        index += 1

def __close_pipe_and_wait(process: subprocess.Popen, subthread: threading.Thread, do_not_raise_permission_error = False, kill=False) -> int:
    try:
        if kill:
            process.terminate()
            subthread.join()
        else:
            subthread.join()
            process.wait()
    except PermissionError:
        if( not do_not_raise_permission_error):
            # 当进程在sudo模式下运行时，无法终止进程，抛出异常
            raise PermissionError("Process is running in root mode. Server can not terminate it. Try run server in root mode.")
    return process.returncode

def __open_pipe_with_multi_process(command: [str], callback: Callable[[subprocess.Popen, str], None]=__callback__print) -> (subprocess.Popen,threading.Thread):
    if command == None:
        raise ValueError("command is None")
    print("运行：", " ".join(command))
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    t = threading.Thread(target=__subthread_reading_worker, args=(process, callback), daemon=True)
    t.start()
    return (process, t)
    

def check_sudo_password() -> OperationResult:
    """
    检查sudo密码是否正确
    
    Args:
        无
    
    Returns:
        OperationResult: 包含操作结果的类，包括code(操作结果码，NO_PASSWORD_PROVIDED表示未提供密码，PASSWORD_INCORRECT表示密码错误，SUCCESS表示密码正确，UNKNWON_ERROR表示未知错误)、status(操作状态，True表示成功，False表示失败)和message(操作结果信息)
    """
    global SUDO_PASSWD
    result = OperationResult(OperationFailedType.WAITING_RESULT, False, "waitting for progress")
    def check_correct(process: subprocess.Popen, output: str, index: int):
        print(f"[{index}]输出：", output)
        nonlocal result
        # if(index != 1): return
        if(output.startswith('sudo: no password was provided')):
            result.code = OperationFailedType.NO_PASSWORD_PROVIDED
            result.status = False
            result.message = "no password was provided"
        elif(output.find('错误密码尝试')!=-1 or output.find('incorrect password attempt')!=-1):
            result.code = OperationFailedType.PASSWORD_INCORRECT
            result.status = False
            result.message = "password incorrect"
        elif(output.startswith('password correct')):
            result.code = OperationFailedType.SUCCESS
            result.status = True
            result.message = "password correct"
        else:
            result.code = OperationFailedType.UNKNWON_ERROR
            result.status = False
            result.message = output
    process, thread = __open_pipe_with_multi_process(['sudo', '-S', 'echo', '"password correct"'],check_correct)
    try:
        process.stdin.write(str(SUDO_PASSWD).encode() + b'\n')
        process.stdin.close()
    except BrokenPipeError:
        pass
    returncode = __close_pipe_and_wait(process, thread, True)
    return result

def set_sudo_password(password: str):
    """
    临时设置sudo密码
    
    Args:
        password (str): sudo密码
    
    Returns:
        None
    """
    global SUDO_PASSWD
    SUDO_PASSWD = password

def __is_need_sudo() -> bool:
    print("检查是否需要sudo权限")
    global SUDO_PASSWD
    result = None
    def get_result(process: subprocess.Popen, output: str, index: int):
        nonlocal result
        print(f"[{index}]输出：", output)
        if(output.find('do not need password')!=-1):
            result = False
        else:
            result = True
    
    process, thread = __open_pipe_with_multi_process(['sudo', '-S', 'echo', '"do not need password"'], get_result)
    try:
        process.stdin.close()
    except BrokenPipeError:
        pass
    returncode = __close_pipe_and_wait(process, thread, True)
    print("需要sudo权限?：", result)
    return result

def check_bin_exist() -> OperationResult:
    """
    检查nwipe是否存在
    
    Args:
        无
    
    Returns:
        OperationResult: 操作结果，包含操作是否成功、操作状态和操作信息
    
    """
    print("检查nwipe是否存在")
    global SUDO_PASSWD, NWIPE_BIN_PATH
    result = OperationResult(OperationFailedType.WAITING_RESULT, False, "waitting for progress")
    def check_correct(process: subprocess.Popen, output: str, index: int):
        print(f"[{index}]输出：", output)
        nonlocal result
        if(output.startswith('nwipe version ')):
            result.code = OperationFailedType.SUCCESS
            result.status = True
            result.message = "OK"
        elif output.find('找不到命令') !=-1 or output.find('command not found') !=-1:
            result.code = OperationFailedType.CANT_FOUND_NWIPE
            result.status = False
            result.message = "can not found nwipe in " + NWIPE_BIN_PATH
        else:
            result.code = OperationFailedType.UNKNWON_ERROR
            result.status = False
            result.message = output
    process, thread = __open_pipe_with_multi_process(['sudo', '-S', NWIPE_BIN_PATH, '--version'], check_correct)
    if __is_need_sudo():
        process.stdin.write(str(SUDO_PASSWD).encode() + b'\n')
        process.stdin.close()
    returncode = __close_pipe_and_wait(process, thread, True)
    return result


def run_nwipe_with_command_line(command: [str], cmd_callback: Callable[[subprocess.Popen, str, int], OperationResult or None] or None=None) -> OperationResult:
    """
    运行nwipe命令行
    
    Args:
        command (List[str]): 运行nwipe命令行需要使用的参数
        cmd_callback (Callable[[subprocess.Popen, str, int], OperationResult or None]): 回调函数，用于处理命令行输出和进程结果
    
    Returns:
        OperationResult: 包含命令执行结果的结构体对象
    
    """
    print("运行nwipe")
    global SUDO_PASSWD, NWIPE_BIN_PATH
    result = OperationResult(OperationFailedType.WAITING_RESULT, False, "waitting for progress")
    def check_correct(process: subprocess.Popen, output: str, index: int):
        print(f"[{index}]输出：", output)
        nonlocal result
        if cmd_callback is None:
            return
        resref = cmd_callback(process, output, index)
        if resref is None:
            return
        # 这里可以做一些事情
        result.code = resref.code
        result.status = resref.status
        result.message = resref.message
    c = ['sudo', '-S', NWIPE_BIN_PATH]
    c.extend(p for p in command)
    process, thread = __open_pipe_with_multi_process(c, check_correct)
    if __is_need_sudo():
        process.stdin.write(str(SUDO_PASSWD).encode() + b'\n')
        process.stdin.close()
    returncode = __close_pipe_and_wait(process, thread, True)
    result.code = returncode
    result.status = returncode == 0
    result.message = ""
    return result

"""
nwipe --verify=last -m dodshort --autonuke --nowait  --nogui /dev/sdd
其中必填的或需要填的有：
--verify：验证执行的时间。  Whether to perform verification of erasure
                          (default: last)
                          off   - Do not verify
                          last  - Verify after the last pass
                          all   - Verify every pass
-m：擦除方法
 -m, --method=METHOD     The wiping method. See man page for more details.
                          (default: dodshort)
                          dod522022m / dod       - 7 pass DOD 5220.22-M method
                          dodshort / dod3pass    - 3 pass DOD method
                          gutmann                - Peter Gutmann's Algorithm
                          ops2                   - RCMP TSSIT OPS-II
                          random / prng / stream - PRNG Stream
                          zero / quick           - Overwrite with zeros
                          one                    - Overwrite with ones (0xFF)
                          verify_zero            - Verifies disk is zero filled
                          verify_one             - Verifies disk is 0xFF filled
-l：日志路径
-P：PDF验证报告路径
-p：PRNG方法             PRNG option (mersenne|twister|isaac|isaac64)
-r：rounds轮次           Number of times to wipe the device using the selected
                          method (default: 1)

其中命令行模式必填的还有：
--nowait：不需等待，直接开始擦除
--nogui：取消GUI模式，开启命令行模式
--autonuke
具体可以通过nwipe --help查看
"""
class Verifies:
    off = "off"
    last = "last"
    all = "all"

class Methods:
    dod522022m = "dod522022m"
    dodshort = "dodshort"
    gutmann = "gutmann"
    ops2 = "ops2"
    random = "random"
    prng = "prng"
    stream = "stream"
    zero = "zero"
    quick = "quick"
    one = "one"
    verify_zero = "verify_zero"
    verify_one = "verify_one"

class PRNGOption:
    mersenne = "mersenne"
    twister = "twister"
    isaac = "isaac"
    isaac64 = "isaac64"

# 这段代码还没有被测试，因为没有环境
def run_nwipe(
        device: str or Device, 
        verify: Verifies.off or Verifies.last or Verifies.all=Verifies.last, 
        method: Methods.dod522022m or Methods.dodshort or Methods.gutmann or Methods.ops2 or Methods.random or Methods.prng or Methods.stream or Methods.zero or Methods.quick or Methods.one or Methods.verify_zero or Methods.verify_one=Methods.dodshort, 
        rounds: int = 1, 
        log_path: str = None, 
        pdf_report_path: str = None, 
        prng_method: PRNGOption.mersenne or PRNGOption.twister or PRNGOption.isaac or PRNGOption.isaac64=None ):
    cmd = ['--autonuke','--nowait','--nogui']
    if verify in [Verifies.off, Verifies.last, Verifies.all]:
        cmd.extend(['--verify', verify])
    else:
        raise ValueError("verify must be in Verifies")
    if method in [Methods.dod522022m, Methods.dodshort, Methods.gutmann, Methods.ops2, Methods.random, Methods.prng, Methods.stream, Methods.zero, Methods.quick, Methods.one, Methods.verify_zero, Methods.verify_one]:
        cmd.extend(['-m', method])
    else:
        raise ValueError("method must be in Methods")
    if type(rounds) == int and rounds > 0:
        cmd.extend(['-r', str(rounds)])
    else:
        raise ValueError("rounds must be int and > 0")
    if log_path:
        cmd.extend(['-l', log_path])
    if pdf_report_path:
        cmd.extend(['-P', pdf_report_path])
    if not (type(prng_method) is None):
        if prng_method in [PRNGOption.mersenne, PRNGOption.twister, PRNGOption.isaac, PRNGOption.isaac64]:
            cmd.extend(['-p', prng_method])
        else:
            raise ValueError("prng_method must be in PRNGOption or None")
    if isinstance(device, Device):
        cmd.append(device.sysdir)
    elif type(device) == str:
        cmd.append(device)
    else:
        raise ValueError("device must be Device or str")
    print("运行nwipe命令：", cmd)
    return run_nwipe_with_command_line(cmd)    
    

__all__ = [check_sudo_password, set_sudo_password, run_nwipe_with_command_line, check_bin_exist, OperationResult, OperationFailedType, run_nwipe, Verifies, Methods, PRNGOption]
                            
if __name__ == "__main__":
    print(check_sudo_password())
    print(__is_need_sudo())
    print(check_bin_exist())
    print(run_nwipe_with_command_line(["--version"]))


