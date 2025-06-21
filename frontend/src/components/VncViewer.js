import React, { useEffect, useRef, useState } from 'react';

const VncViewer = ({ connection, onClose }) => {
  const canvasRef = useRef(null);
  const [isConnected, setIsConnected] = useState(false);
  const [wsConnection, setWsConnection] = useState(null);
  const [screenshot, setScreenshot] = useState(null);

  useEffect(() => {
    if (connection) {
      connectToVnc();
      fetchScreenshot();
    }
    
    return () => {
      if (wsConnection) {
        wsConnection.close();
      }
    };
  }, [connection]);

  const connectToVnc = () => {
    const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
    const wsUrl = `${BACKEND_URL.replace('https://', 'wss://').replace('http://', 'ws://')}/ws/vnc/${connection.id}`;
    
    const ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      console.log('VNC WebSocket connected');
      setIsConnected(true);
      setWsConnection(ws);
    };
    
    ws.onmessage = (event) => {
      console.log('VNC message:', event.data);
      // В реальной реализации здесь будет обработка VNC данных
    };
    
    ws.onclose = () => {
      console.log('VNC WebSocket disconnected');
      setIsConnected(false);
      setWsConnection(null);
    };
    
    ws.onerror = (error) => {
      console.error('VNC WebSocket error:', error);
      setIsConnected(false);
    };
  };

  const fetchScreenshot = async () => {
    try {
      const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
      const response = await fetch(`${BACKEND_URL}/api/vnc/${connection.id}/screenshot`);
      const svgText = await response.text();
      setScreenshot(svgText);
    } catch (error) {
      console.error('Error fetching screenshot:', error);
    }
  };

  const sendMouseEvent = (event) => {
    if (wsConnection && isConnected) {
      const rect = canvasRef.current.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      
      wsConnection.send(JSON.stringify({
        type: 'mouse',
        x: Math.floor(x),
        y: Math.floor(y),
        button: event.button,
        action: event.type
      }));
    }
  };

  const sendKeyEvent = (event) => {
    if (wsConnection && isConnected) {
      wsConnection.send(JSON.stringify({
        type: 'key',
        key: event.key,
        code: event.code,
        action: event.type
      }));
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-90 z-50 flex flex-col">
      {/* Заголовок */}
      <div className="bg-gray-800 text-white p-4 flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold">🖥️ VNC Viewer - {connection.name}</h2>
          <p className="text-sm text-gray-300">
            {connection.ip_address}:{connection.vnc_port} | 
            Status: {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
          </p>
        </div>
        <div className="flex space-x-2">
          <button
            onClick={fetchScreenshot}
            className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition-colors"
          >
            🔄 Refresh
          </button>
          <button
            onClick={onClose}
            className="bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700 transition-colors"
          >
            ✕ Close
          </button>
        </div>
      </div>

      {/* VNC Canvas */}
      <div className="flex-1 flex items-center justify-center p-4">
        <div className="relative max-w-full max-h-full">
          {screenshot ? (
            <div
              className="border border-gray-600 rounded-lg overflow-hidden cursor-pointer bg-white"
              onMouseDown={sendMouseEvent}
              onMouseUp={sendMouseEvent}
              onMouseMove={sendMouseEvent}
              onKeyDown={sendKeyEvent}
              onKeyUp={sendKeyEvent}
              tabIndex={0}
              ref={canvasRef}
              dangerouslySetInnerHTML={{ __html: screenshot }}
            />
          ) : (
            <div className="w-[800px] h-[600px] bg-gray-900 border border-gray-600 rounded-lg flex items-center justify-center">
              <div className="text-center text-white">
                <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-white mx-auto mb-4"></div>
                <p>Loading VNC Screen...</p>
              </div>
            </div>
          )}
          
          {/* Overlay с информацией о подключении */}
          {!isConnected && (
            <div className="absolute inset-0 bg-black bg-opacity-50 flex items-center justify-center">
              <div className="bg-white p-6 rounded-lg text-center">
                <p className="text-lg font-medium mb-2">🔌 Establishing VNC Connection...</p>
                <p className="text-sm text-gray-600">
                  Connecting to {connection.ip_address}:{connection.vnc_port}
                </p>
                <div className="mt-4">
                  <div className="animate-pulse bg-blue-500 h-2 rounded"></div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Панель управления */}
      <div className="bg-gray-800 text-white p-4">
        <div className="flex justify-between items-center">
          <div className="flex space-x-4">
            <button
              onClick={() => sendKeyEvent({ key: 'Control', code: 'ControlLeft', type: 'keydown' })}
              className="bg-gray-700 px-3 py-1 rounded text-sm hover:bg-gray-600 transition-colors"
            >
              Ctrl
            </button>
            <button
              onClick={() => sendKeyEvent({ key: 'Alt', code: 'AltLeft', type: 'keydown' })}
              className="bg-gray-700 px-3 py-1 rounded text-sm hover:bg-gray-600 transition-colors"
            >
              Alt
            </button>
            <button
              onClick={() => sendKeyEvent({ key: 'Delete', code: 'Delete', type: 'keydown' })}
              className="bg-gray-700 px-3 py-1 rounded text-sm hover:bg-gray-600 transition-colors"
            >
              Del
            </button>
            <button
              onClick={() => sendKeyEvent({ key: 'Tab', code: 'Tab', type: 'keydown' })}
              className="bg-gray-700 px-3 py-1 rounded text-sm hover:bg-gray-600 transition-colors"
            >
              Tab
            </button>
          </div>
          
          <div className="text-sm text-gray-400">
            Click and type to interact with remote desktop
          </div>
        </div>
      </div>
    </div>
  );
};

export default VncViewer;