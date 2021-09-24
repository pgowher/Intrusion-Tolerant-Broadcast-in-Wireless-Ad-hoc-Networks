
package inet.examples.myadhoc;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.AdhocHost;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.contract.IIntegratedVisualizer;
import inet.physicallayer.unitdisk.UnitDiskRadioMedium;

// Defind the Malicious Host
module MaliciousHost extends AdhocHost
{
    @display("i2=status/excl;i=,red,60");
}

// Network topology
network MyAdhocNetwork
{
    parameters:
        // number of malicious host (default: 10)
        int numMalHosts = default(10);

        // number of normal hosts (numMalhost * 2 + rand between 1 & 10)
        int numHosts = numMalHosts * 2 + intuniform(1, 10);
    submodules:
        // visualizer module
        visualizer: <default("IntegratedCanvasVisualizer")> like IIntegratedVisualizer if hasVisualizer() {
            parameters:
                @display("p=100,300;is=s");
        }

        // configurator module
        configurator: Ipv4NetworkConfigurator {
            parameters:
                @display("p=100,100;is=s");
        }

        // radio medium module
        radioMedium: Ieee80211ScalarRadioMedium {
            parameters:
                @display("p=100,200;is=s");
        }

        // Normal Hosts
        NormalHost[numHosts]: AdhocHost {
            parameters:
                @display("p=375.496,198.79199;is=s");
        }

		// Malicious Hosts
        MalHost[numMalHosts]: MaliciousHost {
            @display("is=s;p=847.376,198.79199");
        }
}
