import logging
import time

from virttest import utils_test
from virttest import utils_net
from virttest import error_context
from virttest.utils_windows import virtio_win


@error_context.context_aware
def run(test, params, env):
    """
    The rx/tx offload checksum test for windows
    1) start vm
    2) set the tx/rx offload checksum of the netkvm driver to tcp
    3) restart nic, and run file transfer test
    4) set the tx/rx offload checksum of the nekvm driver to disable
    5) restart nic, and run file transfer test again

    param test: the test object
    param params: the test params
    param env: test environment
    """

    def get_netkvmco_path(session):
        """
        Get the proper netkvmco.dll path from iso.

        :param session: a session to send cmd
        :return: the proper netkvmco.dll path
        """

        viowin_ltr = virtio_win.drive_letter_iso(session)
        if not viowin_ltr:
            err = "Could not find virtio-win drive in guest"
            test.error(err)
        guest_name = virtio_win.product_dirname_iso(session)
        if not guest_name:
            err = "Could not get product dirname of the vm"
            test.error(err)
        guest_arch = virtio_win.arch_dirname_iso(session)
        if not guest_arch:
            err = "Could not get architecture dirname of the vm"
            test.error(err)

        middle_path = "%s\\%s" % (guest_name, guest_arch)
        find_cmd = 'dir /b /s %s\\netkvmco.dll | findstr "\\%s\\\\"'
        find_cmd %= (viowin_ltr,  middle_path)
        netkvmco_path = session.cmd(find_cmd).strip()
        logging.info("Found netkvmco.dll file at %s" % netkvmco_path)
        return netkvmco_path

    def start_test(type="tcp"):
        """
        Start tx/tx offload checksum test. First set tx/rx offload checksum
        value to the driver, the restart the nic and run file transfertest,

        param type: the setting type for checksum, tcp or disable
        """

        error_context.context("Start set tx/rx checksum offload to %s" % type, logging.info)
        offload_checksum_cmd = params.get("offload_checksum_cmd")
        rx_param = params.get("rx_param")
        tx_param = params.get("tx_param")
        if type == "tcp":
            value = params.get("value_tcp")
        else:
            value = params.get("value_disable")

        rx_cmd = offload_checksum_cmd % (rx_param, value)
        tx_cmd = offload_checksum_cmd % (tx_param, value)
        try:
            session = vm.wait_for_serial_login(timeout=timeout)
            logging.info("Set rx offload checksum to %s" % type)
            status, output = session.cmd_status_output(rx_cmd)
            if status:
                test.error("Error occured when set rx offload checksum: "
                           "status=%s, output=%s" % (status, output))
            logging.info("Set rt offload checksum to %s" % type)
            status, output = session.cmd_status_output(tx_cmd)
            if status:
                test.error("Error occured when set tx offload checksum: "
                           "status=%s, output=%s" % (status, output))
            logging.info("Restart nic to apply changes")
            dev_mac = vm.virtnet[0].mac
            connection_id = utils_net.get_windows_nic_attribute(
                session, "macaddress", dev_mac, "netconnectionid")
            utils_net.restart_windows_guest_network(
                session, connection_id)
            time.sleep(10)
            error_context.context("Start file transfer test", logging.info)
            utils_test.run_file_transfer(test, params, env)
        finally:
            session.close()

    timeout = params.get("timeout", 360)
    vm = env.get_vm(params["main_vm"])
    vm.verify_alive()
    prepare_netkvmco_cmd = params.get("prepare_netkvmco_cmd")

    session = vm.wait_for_login(timeout=timeout)
    error_context.context("Check if the driver is installed and "
                          "verified", logging.info)
    driver_name = params.get("driver_name", "netkvm")
    session = utils_test.qemu.windrv_check_running_verifier(session, vm,
                                                            test,
                                                            driver_name,
                                                            timeout)
    netkvmco_path = get_netkvmco_path(session)
    session.cmd(prepare_netkvmco_cmd % netkvmco_path, timeout=240)
    session.close()

    start_test("tcp")
    start_test("disable")
