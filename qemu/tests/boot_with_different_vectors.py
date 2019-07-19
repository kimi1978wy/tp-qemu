import logging
import re

from virttest import error_context
from virttest import utils_test
from virttest import env_process
from virttest import virt_vm
from virttest import utils_net


@error_context.context_aware
def run(test, params, env):
    """
    Boot guest with different vectors, then do netperf testing.

    1) Boot up VM with vectors.
    2) Enable multi queues in guest.
    3) Check guest pci msi support.
    4) Check the cpu interrupt of virito driver.
    5) Run netperf test in guest.
    6) Repeat step 1 ~ step 5 with different vectors.

    :param test: QEMU test object.
    :param params: Dictionary with the test parameters.
    :param env: Dictionary with test environment.
    """

    def boot_guest_with_vectors(vectors):
        error_context.context("Boot guest with vectors = %s" % vectors,
                              logging.info)
        params["vectors"] = vectors
        params["start_vm"] = "yes"
        try:
            env_process.preprocess_vm(test, params, env, params.get("main_vm"))
        except virt_vm.VMError as err:
            if int(vectors) < 0:
                txt = "Parameter 'vectors' expects uint32_t"
                if re.findall(txt, str(err)):
                    return
        if int(vectors) < 0:
            msg = "Qemu did not raise correct error"
            msg += " when vectors = %s" % vectors
            test.fail(msg)

        vm = env.get_vm(params["main_vm"])
        vm.verify_alive()
        return vm

    def check_msi_support(session):
        vectors = int(params["vectors"])
        if params["os_type"] == "linux":
            devices = session.cmd_output("lspci | grep Eth").strip()
            error_context.context("Check if vnic inside guest support msi.",
                                  logging.info)
            for device in devices.split("\n"):
                if not device:
                    continue
                d_id = device.split()[0]
                msi_check_cmd = params["msi_check_cmd"] % d_id
                output = session.cmd_output(msi_check_cmd)
                if vectors == 0 and output:
                    test.fail("Guest do not support msi when vectors = 0.")
                if output:
                    if vectors == 1:
                        if "MSI-X: Enable-" in output:
                            logging.info("MSI-X is disabled")
                        else:
                            msg = "Command %s get wrong output." % msi_check_cmd
                            msg += " when vectors = 1"
                            test.fail(msg)
                    else:
                        if "MSI-X: Enable+" in output:
                            logging.info("MSI-X is enabled")
                        else:
                            msg = "Command %s get wrong output." % msi_check_cmd
                            msg += " when vectors = %d" % vectors
                            test.fail(msg)
        else:
            error_context.context("Check if the driver is installed and "
                                  "verified", logging.info)
            driver_name = params.get("driver_name", "netkvm")
            session = utils_test.qemu.windrv_check_running_verifier(session, vm,
                                                                    test,
                                                                    driver_name,
                                                                    cmd_timeout)
            msis, queues = utils_net.get_msis_and_queues_windows(params, vm)
            if None in (msis, queues):
                test.fail("Can't get msi status from guest.")
            if vectors == 0 and msis != 0 and queues != 1:
                test.fail("Msis should be 0, queues should be 1  when vectors = 1,"
                          " but guest msis = %s, queues = %s" % (msis, queues))
            elif vectors != msis:
                test.fail("Msis should equal to vectors(%s), but guest is %s" % (vectors, msis))

    def check_interrupt(session, vectors):
        error_context.context("Check the cpu interrupt of virito",
                              logging.info)
        vectors = int(vectors)
        irq_check_cmd = params["irq_check_cmd"]
        output = session.cmd_output(irq_check_cmd).strip()
        if vectors == 0 or vectors == 1:
            if not (re.findall("IO-APIC.*fasteoi|XICS.*Level|XIVE.*Level",
                               output)):
                msg = "Could not find interrupt controller for virito device"
                msg += " when vectors = %d" % vectors
                test.fail(msg)
        elif 2 <= vectors and vectors <= 8:
            if not re.findall("virtio[0-9]-virtqueues", output):
                msg = "Could not find the virtio device for MSI-X interrupt"
                msg += " when vectors = %d " % vectors
                msg += "Command %s got output %s" % (irq_check_cmd, output)
                test.fail(msg)
        elif vectors == 9 or vectors == 10:
            if not (re.findall("virtio[0-9]-input", output) and
                    re.findall("virtio[0-9]-output", output)):
                msg = "Could not find the virtio device for MSI-X interrupt"
                msg += " when vectors = %d " % vectors
                msg += "Command %s got output %s" % (irq_check_cmd, output)
                test.fail(msg)

    vectors_list = params["vectors_list"]
    login_timeout = int(params.get("login_timeout", 360))
    cmd_timeout = int(params.get("cmd_timeout", 240))
    sub_test = params.get("sub_test_name", "netperf_stress")
    for vectors in vectors_list.split():
        vm = boot_guest_with_vectors(vectors)
        if int(vectors) < 0:
            continue
        session = vm.wait_for_login(timeout=login_timeout)
        check_msi_support(session)
        if params["os_type"] == "linux":
            check_interrupt(session, vectors)
        error_context.context("Run netperf test in guest.", logging.info)
        utils_test.run_virt_sub_test(test, params, env, sub_type=sub_test)
