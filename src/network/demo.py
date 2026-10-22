"""Run the isolated Mininet demonstration stack (requires Linux and root)."""
import argparse
import os
import shutil
import signal
import subprocess
import sys
import time

from ..utils.config import config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--topology', choices=('simple', 'realistic', 'scalable'), default='simple')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('the live Mininet lab requires Linux and root; run with sudo')
    missing = [name for name in ('ovs-vsctl', 'suricata') if not shutil.which(name)]
    try:
        import mininet  # noqa: F401
    except ImportError:
        missing.append('Mininet (Python package)')
    if missing:
        parser.error('missing live prerequisites: ' + ', '.join(missing) +
                     '. Run bash scripts/setup_environment.sh --live on Ubuntu 22.04/24.04.')

    from .topology import NetworkTopology

    root = config.root
    logs = root / 'logs'
    (logs / 'suricata').mkdir(parents=True, exist_ok=True)
    (root / '.run').mkdir(exist_ok=True)
    python = sys.executable
    children = []
    handles = []
    topology = NetworkTopology()

    def launch(name, command):
        handle = open(logs / f'{name}.log', 'a', buffering=1)
        handles.append(handle)
        proc = subprocess.Popen(command, cwd=root, stdout=handle, stderr=subprocess.STDOUT)
        children.append(proc)
        time.sleep(1)
        if proc.poll() is not None:
            raise RuntimeError(f'{name} exited during startup; inspect logs/{name}.log')
        return proc

    try:
        if args.topology == 'simple':
            topology.create_simple_topology()
        elif args.topology == 'realistic':
            topology.create_realistic_topology()
        else:
            topology.create_scalable_topology()
        topology.start()

        launch('controller', [python, '-m', 'os_ken.cmd.manager', '--observe-links',
                              'src.controller.sdn_controller'])
        sensor_interface = 's1-eth1' if args.topology == 'realistic' else 's1-eth2'
        launch('suricata', ['suricata', f'--af-packet={sensor_interface}', '-c',
                            str(root / 'config/suricata.yaml'), '-S',
                            str(root / 'src/detection/rules/custom.rules'),
                            '-l', str(logs / 'suricata')])
        launch('orchestrator', [python, '-m', 'orchestrator.orchestrator',
                                '--eve', str(logs / 'suricata/eve.json'),
                                '--db', str(logs / 'incidents.db'),
                                '--ryu-url', 'http://127.0.0.1:8080', '--api-port', '5001',
                                '--protected', '10.0.0.254'])
        launch('dashboard', [python, '-m', 'src.dashboard.app'])

        print('Live isolated Mininet lab is running.')
        print('Dashboard: http://127.0.0.1:5000  |  Incidents: http://127.0.0.1:5000/incidents')
        print('Open the Mininet CLI below (try: pingall, h1 ping -c 1 10.0.0.2). Ctrl-D stops all services.')
        topology.cli()
    except KeyboardInterrupt:
        pass
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
        for child in reversed(children):
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        topology.stop()
        for handle in handles:
            handle.close()


if __name__ == '__main__':
    main()
