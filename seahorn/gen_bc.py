import argparse
import yaml
import json
import os
from subprocess import Popen
import shutil

SEA_YAML_FILE = 'sea.yaml'
SRC_PATH = 'src_path'
SEA_OPTIONS = 'sea_options'
TARGETS = 'targets'
JOBS_DIR = 'jobs'
VERI_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.dirname(VERI_PATH)
HELPER_PATH = os.path.join(VERI_PATH, 'include')
COMPILE_CMDS_FILE = 'compile_commands.json'

def isexec(fpath):
    if fpath == None: return False
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def get_job_info(job_path):
    src_path = None
    sea_options = None
    targets = None
    with open(os.path.join(job_path, SEA_YAML_FILE)) as yf:
        data = yaml.load(yf, Loader=yaml.SafeLoader)
        if data:
            src_path = data[SRC_PATH]
            sea_options = data[SEA_OPTIONS]
            targets = data[TARGETS]
    return src_path, sea_options, targets

def get_clang():
    clang_cmd = None
    for clang_ver in ['clang-mp-5.0', 'clang-5.0', 'clang']:
        clang_cmd = shutil.which(clang_ver)
        if clang_cmd != None:
            return clang_cmd
    return clang_cmd

def get_sea():
    sea = None
    if 'SEAHORN' in os.environ and isexec(os.environ['SEAHORN']):
        sea = os.environ['SEAHORN']
    return sea

def get_seahorn_dir():
    # Find full path to seahorn headers
    sea_dir = None
    sea = get_sea()
    if sea:
        run_dir = os.path.dirname(os.path.dirname(sea))
        sea_dir = os.path.join(run_dir, 'include')
    return sea_dir


# generate .bc file for main harness .cpp file and stubbed files
def generate_bitcode(clang_cmd, sea_dir, target, sea_options, comp_options, dry=False, verbose=False):
    command = [clang_cmd]
    # append path to custom stubbed code
    command.append("-I{helper_dir}".format(helper_dir=HELPER_PATH))
    # remove first element: we want to use our version of clang instead of
    # trusty's prebuilt compiler
    # remove last element: not compiling the actual source, instead
    # emit LLVM IR for <target>
    command.extend(comp_options[1:len(comp_options)-1])
    # append sea clang options
    command.extend(sea_options)
    command.append("-I{sea_dir}".format(sea_dir=sea_dir))
    outfile = "{target}.bc".format(target=target)
    command.append("-o {outfile}".format(outfile=outfile))
    command.append(target)
    command_str = " ".join(command)
    if dry or verbose:
        print(command_str)
    if not dry:
        clang_p = Popen(command_str, shell=True)
        _, err = clang_p.communicate()
        if not err and os.path.isfile(outfile):
            print("generated output bitcode in %s" % outfile)
        else:
            print("error generating bitcode: %s" % err)

# use sea clang to link everything into a single file
def link_targets(targets, job_path, dry=False, verbose=False):
    sea_cmd = get_sea()
    if not sea_cmd:
        print("sea not available, skipping link...")
        return
    outfile = os.path.join(job_path, "out.bc")
    bc_targets = [
        os.path.join(ROOT_PATH, "{target}.bc".format(target=t)) for t in targets
    ]
    command = [sea_cmd, 'clang', '-S', '-o', outfile, *bc_targets]
    command_str = " ".join(command)
    if dry or verbose:
        print(command_str)
    if not dry:
        sea_p = Popen(command_str, shell=True)
        _, err = sea_p.communicate()
        if not err and os.path.isfile(outfile):
            print("linked output bitcode in %s" % outfile)
        else:
            print("error linking for %s: %s" % (job_path, err))

def parse_compile_commands():
    cc_dict = dict()
    compile_commands_path = os.path.join(ROOT_PATH, COMPILE_CMDS_FILE)
    if not os.path.exists(compile_commands_path):
        print("Cannot find {file} under {path}.".format(
                file=COMPILE_CMDS_FILE, path=ROOT_PATH))
        return None
    with open(compile_commands_path) as cc:
        data = json.load(cc)
        if not data:
            print("Nothing in compile commands db")
            return None
        for target in data:
            cc_dict[target['file']] = target.get('arguments', [])
    return cc_dict


def main():
    parser = argparse.ArgumentParser(description="Generates LLVM IR bitcode for all jobs under seahorn/jobs")
    parser.add_argument('--dry', action="store_true", default=False)
    parser.add_argument('--verbose', action="store_true", default=False)
    options = parser.parse_args()
    sea_dir = get_seahorn_dir()
    dry = options.dry
    verbose = options.verbose
    if not sea_dir:
        if not dry:
            print('Please add sea executable to environment variables!')
            return -1
        else:
            sea_dir = "seahorn/build/run/include"

    clang_cmd = get_clang()
    if not clang_cmd:
        print("No clang found")
        return -1

    compile_commands = parse_compile_commands()
    if not compile_commands:
        print("No compile commands available")
        return -1
    
    full_jobs_path = os.path.join(VERI_PATH, JOBS_DIR)
    for job in os.listdir(full_jobs_path):
        job_path = os.path.join(full_jobs_path, job)
        if os.path.isdir(job_path):
            src_path, sea_option, targets = get_job_info(job_path)
            if src_path and sea_option and targets:
                compile_option = compile_commands.get(src_path)
                for target in targets:
                    target_path = os.path.join(ROOT_PATH, target)
                    generate_bitcode(
                        clang_cmd,
                        sea_dir,
                        target_path,
                        sea_option.split(" "),
                        compile_option,
                        dry=dry,
                        verbose=verbose)
                link_targets(targets, job_path, dry=dry, verbose=verbose)
            else:
                print("No src file or option found for %s. Skiping" % job_path)
    return 0


if __name__ == "__main__":
    main()
