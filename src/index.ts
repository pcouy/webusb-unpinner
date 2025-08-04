import { AdbDaemonWebUsbDeviceObserver } from "@yume-chan/adb-daemon-webusb";

const statusDiv = document.getElementById('status')!;
const connectBtn = document.getElementById('connectBtn') as HTMLButtonElement;

if (!navigator.usb) {
    statusDiv.textContent = 'WebUSB not supported. Use Chroimum-based browsers.';
    statusDiv.className = 'status disabled';
    connectBtn.disabled = true;
}

let observer: AdbDaemonWebUsbDeviceObserver | null = null;

// Update UI based on connection state
function updateStatus(devices: readonly unknown[] = []) {
    if (devices.length > 0) {
        statusDiv.textContent = 'ADB enabled!';
        statusDiv.className = 'status enabled';
    } else {
        statusDiv.textContent = 'No ADB device connected';
        statusDiv.className = 'status disabled';
    }
}

async function initializeObserver() {
    try {
        observer = await AdbDaemonWebUsbDeviceObserver.create(navigator.usb, {
            filters: [{vendorId: 0x18d1}]
        });

        updateStatus(observer.current);

        // Listen for device list changes
        observer.onListChange(devices => {
            updateStatus(devices)
        });

        // Handle device connection events
        observer.onDeviceAdd(devices => {
            console.log('Device connected: ', devices);
        });

        observer.onDeviceRemove(devices => {
            console.log('Device disconnected: ', devices);
        });

    } catch (error) {
        console.error('Observer Initialization failed: ', error);
        statusDiv.textContent = 'Failed to initialize observer';
    }
}

connectBtn.addEventListener('click', async () => {
    try {
        await navigator.usb.requestDevice({
            filters: [{ vendorId: 0x18d1}]
        });
    } catch (error) {
        console.log('Device selection cancelled');
    }
});

window.addEventListener('beforeunload', () => {
    if (observer) {
        observer.stop(); // Release resources
    }
});

initializeObserver();
