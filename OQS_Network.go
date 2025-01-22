// OQS-GO
// Aaron Stovall

package oqs

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
)

// Network encapsulates secure network communication.
type Network struct {
	TLSConfig   *tls.Config
	Connections map[string]net.Conn
	mutex       sync.RWMutex
}

// NewNetwork initializes a new Network instance with default TLS settings.
func NewNetwork() *Network {
	return &Network{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
		Connections: make(map[string]net.Conn),
	}
}

// Connect establishes a secure connection to the given address.
func (n *Network) Connect(address string) (net.Conn, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if _, exists := n.Connections[address]; exists {
		return nil, fmt.Errorf("already connected to %s", address)
	}

	conn, err := tls.Dial("tcp", address, n.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}

	n.Connections[address] = conn
	return conn, nil
}

// Send sends data securely to the specified address.
func (n *Network) Send(address string, data []byte) error {
	n.mutex.RLock()
	conn, exists := n.Connections[address]
	n.mutex.RUnlock()

	if !exists {
		return errors.New("connection not found")
	}

	_, err := conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send data to %s: %w", address, err)
	}

	return nil
}

// Receive reads data securely from the specified address.
func (n *Network) Receive(address string, buffer []byte) (int, error) {
	n.mutex.RLock()
	conn, exists := n.Connections[address]
	n.mutex.RUnlock()

	if !exists {
		return 0, errors.New("connection not found")
	}

	nBytes, err := conn.Read(buffer)
	if err != nil {
		return 0, fmt.Errorf("failed to read data from %s: %w", address, err)
	}

	return nBytes, nil
}

// Disconnect closes the secure connection to the specified address.
func (n *Network) Disconnect(address string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	conn, exists := n.Connections[address]
	if !exists {
		return errors.New("connection not found")
	}

	err := conn.Close()
	if err != nil {
		return fmt.Errorf("failed to disconnect from %s: %w", address, err)
	}

	delete(n.Connections, address)
	return nil
}

// Broadcast sends data securely to all connected addresses.
func (n *Network) Broadcast(data []byte) error {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for address, conn := range n.Connections {
		if _, err := conn.Write(data); err != nil {
			return fmt.Errorf("failed to send data to %s: %w", address, err)
		}
	}

	return nil
}

// ExampleUsage demonstrates secure network operations.
func NetworkExampleUsage() {
	network := NewNetwork()

	address := "example.com:443"
	conn, err := network.Connect(address)
	if err != nil {
		fmt.Println("Connection error:", err)
		return
	}
	defer network.Disconnect(address)

	message := []byte("Hello, Secure World!")
	if err := network.Send(address, message); err != nil {
		fmt.Println("Send error:", err)
		return
	}

	buffer := make([]byte, 1024)
	nBytes, err := network.Receive(address, buffer)
	if err != nil {
		fmt.Println("Receive error:", err)
		return
	}

	fmt.Printf("Received (%d bytes): %s\n", nBytes, string(buffer[:nBytes]))
}
