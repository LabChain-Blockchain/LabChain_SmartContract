#[starknet::interface]
trait IDeviceRegistry<TContractState> {
    fn register_device(
        ref self: TContractState,
        device_type: felt252,
        serial_number: felt252,
        admin: felt252
    );
    fn get_device(self: @TContractState, serial_number: felt252) -> Device;
}

#[derive(Drop, Serde, Copy, starknet::Store)]
struct Device {
    serial_number: felt252,
    device_type: felt252,
    admin: felt252
}

#[starknet::contract]
mod DeviceRegistry {
    use starknet::storage::{
        StorageMapReadAccess,
        StorageMapWriteAccess,
        Map
    };
    use super::Device;
    use super::IDeviceRegistry;

    #[storage]
    struct Storage {
        devices: Map<felt252, Device>
    }

    #[abi(embed_v0)]
    pub impl DeviceRegistryImp of IDeviceRegistry<ContractState> {
        
        /// Registra un nuevo dispositivo
        fn register_device(ref self: ContractState, device_type: felt252, serial_number: felt252, admin: felt252) {
            // Validar que no exista
            let existing = self.devices.read(serial_number);
            assert(existing.device_type != 0, 'Device not found.');

            let device = Device {
                serial_number,
                device_type,
                admin
            };

            self.devices.write(serial_number, device);
        }

        fn get_device(self: @ContractState, serial_number: felt252) -> Device {
            let device = self.devices.read(serial_number);
            assert(device.device_type != 0, 'Device not found.');
            device
        }
    }
}
