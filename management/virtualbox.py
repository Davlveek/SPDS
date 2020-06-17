import vboxapi


class VirtualBox:
    def __init__(self):
        self.mgr = vboxapi.VirtualBoxManager(None, None)
        self.vbox = self.mgr.getVirtualBox()

    def get_session(self, vm):
        try:
            mach = self.vbox.findMachine(vm)
            session = self.mgr.getSessionObject(mach)
            mach.lockMachine(session, 1)
            return session
        except Exception as e:
            print(f'Exception: {e}')
            return 'error'

    def power_on(self, vm):
        try:
            mach = self.vbox.findMachine(vm)
            session = self.mgr.getSessionObject(mach)
            progress = mach.launchVMProcess(session, 'gui', '')
            progress.waitForCompletion(-1)
        except Exception as e:
            print(f'Exception: {e}')
        finally:
            self.mgr.closeMachineSession(session)

    def power_off(self, vm):
        session = self.get_session(vm)
        if session == 'error':
            return

        try:
            progress = session.console.powerDown()
            progress.waitForCompletion(-1)
        except Exception as e:
            print(f'Exception: {e}')
        finally:
            session.unlockMachine()

    def restore_snapshot(self, vm, snapshot):
        session = self.get_session(vm)
        if session == 'error':
            return

        try:
            progress = session.machine.restoreSnapshot(session.machine.findSnapshot(snapshot))
            progress.waitForCompletion(-1)
        except Exception as e:
            print(f'Exception: {e}')
        finally:
            session.unlockMachine()


if __name__ == '__main__':
    virtm = "IDA+DynamoRIO"
    snap = 'test_snapshot'

    test = VirtualBox()
    test.restore_snapshot(virtm, snap)
    test.power_on(virtm)

