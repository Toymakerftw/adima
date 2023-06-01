document.addEventListener('DOMContentLoaded', function() {
    const socket = io.connect(window.location.protocol + '//' + document.domain + ':' + location.port);

    socket.on('connect', function() {
        console.log('Connected to the server');
        socket.emit('request_stats');
    });

    socket.on('update_stats', function(data) {
        updateStats(data);
    });

    socket.on('disconnect', function() {
        console.log('Disconnected from the server');
    });


    function updateStats(data) {
        const statsContainer = document.getElementById('stats-container');
        statsContainer.innerHTML = '';

        const uptimeElement = document.createElement('p');
        uptimeElement.textContent = `Uptime: ${data.uptime}`;
        statsContainer.appendChild(uptimeElement);

        const cpuUsageElement = document.createElement('p');
        cpuUsageElement.textContent = `CPU Usage: ${data.cpu_usage}%`;
        statsContainer.appendChild(cpuUsageElement);

        const memoryUsageElement = document.createElement('p');
        memoryUsageElement.textContent = `Memory Usage: Total: ${data.memory_usage.total}, Available: ${data.memory_usage.available}, Used: ${data.memory_usage.used}, Percentage: ${data.memory_usage.percent}%`;
        statsContainer.appendChild(memoryUsageElement);

        const storageUsageElement = document.createElement('p');
        storageUsageElement.textContent = 'Storage Usage:';
        statsContainer.appendChild(storageUsageElement);

        const storageList = document.createElement('ul');
        storageList.classList.add('storage-list'); // Add class to the <ul> element
        for (const [device, usage] of Object.entries(data.storage_usage)) {
            const storageItem = document.createElement('li');
            storageItem.classList.add('storage-item'); // Add class to each <li> element
            storageItem.textContent = `${device}: Total: ${usage.total}, Used: ${usage.used}, Free: ${usage.free}, Percentage: ${usage.percent}%`;
            storageList.appendChild(storageItem);
        }
        statsContainer.appendChild(storageList);

        const networkTrafficElement = document.createElement('p');
        networkTrafficElement.classList.add('network-traffic'); // Add class to the <p> element
        networkTrafficElement.textContent = `Network Traffic: Bytes Sent: ${data.traffic.bytes_sent}, Bytes Received: ${data.traffic.bytes_recv}`;
        statsContainer.appendChild(networkTrafficElement);
    }
});
