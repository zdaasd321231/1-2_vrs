import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';
import VncViewer from './components/VncViewer';
import FileManager from './components/FileManager';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Компонент для отображения карточки VNC соединения
const ConnectionCard = ({ connection, onGenerateInstaller, onConnect, onDelete, onFileManager }) => {
  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'bg-green-100 text-green-800 border-green-200';
      case 'inactive': return 'bg-gray-100 text-gray-800 border-gray-200';
      case 'installing': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'error': return 'bg-red-100 text-red-800 border-red-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'active': return '🟢';
      case 'inactive': return '🔴';
      case 'installing': return '🟡';
      case 'error': return '❌';
      default: return '⚪';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6 border border-gray-200 hover:shadow-lg transition-shadow">
      <div className="flex justify-between items-start mb-4">
        <div>
          <h3 className="text-lg font-semibold text-gray-900 mb-1">{connection.name}</h3>
          <p className="text-sm text-gray-600 mb-2">{connection.location}</p>
          <p className="text-xs text-gray-500">{connection.country}, {connection.city}</p>
        </div>
        <div className="flex flex-col items-end">
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getStatusColor(connection.status)}`}>
            {getStatusIcon(connection.status)} {connection.status}
          </span>
          {connection.ip_address && (
            <p className="text-xs text-gray-500 mt-1">{connection.ip_address}</p>
          )}
        </div>
      </div>
      
      <div className="grid grid-cols-2 gap-4 text-sm text-gray-600 mb-4">
        <div>
          <span className="font-medium">Порт VNC:</span> {connection.vnc_port}
        </div>
        <div>
          <span className="font-medium">Создано:</span> {new Date(connection.created_at).toLocaleDateString()}
        </div>
        <div>
          <span className="font-medium">Ключ:</span> {connection.installation_key}
        </div>
        <div>
          <span className="font-medium">Последняя активность:</span>{' '}
          {connection.last_seen ? new Date(connection.last_seen).toLocaleString() : 'Никогда'}
        </div>
      </div>

      <div className="flex space-x-2">
        <button
          onClick={() => onGenerateInstaller(connection.id)}
          className="flex-1 bg-blue-600 text-white px-3 py-2 rounded-md text-sm font-medium hover:bg-blue-700 transition-colors"
        >
          📥 Скачать установщик
        </button>
        
        {connection.status === 'active' && (
          <>
            <button
              onClick={() => onConnect(connection.id)}
              className="flex-1 bg-green-600 text-white px-3 py-2 rounded-md text-sm font-medium hover:bg-green-700 transition-colors"
            >
              🖥️ Подключиться
            </button>
            <button
              onClick={() => onFileManager(connection.id)}
              className="flex-1 bg-purple-600 text-white px-3 py-2 rounded-md text-sm font-medium hover:bg-purple-700 transition-colors"
            >
              📁 Файлы
            </button>
          </>
        )}
        
        <button
          onClick={() => onDelete(connection.id)}
          className="bg-red-600 text-white px-3 py-2 rounded-md text-sm font-medium hover:bg-red-700 transition-colors"
        >
          🗑️
        </button>
      </div>
    </div>
  );
};

// Компонент для создания нового соединения
const CreateConnectionModal = ({ isOpen, onClose, onCreateConnection }) => {
  const [formData, setFormData] = useState({
    name: '',
    location: '',
    country: 'Russia',
    city: 'Moscow'
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    onCreateConnection(formData);
    setFormData({ name: '', location: '', country: 'Russia', city: 'Moscow' });
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md">
        <h2 className="text-xl font-bold mb-4">Создать новое VNC соединение</h2>
        
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Название компьютера
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Например: Компьютер Лаборатория 1"
              required
            />
          </div>

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Местоположение
            </label>
            <input
              type="text"
              value={formData.location}
              onChange={(e) => setFormData({ ...formData, location: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Например: Главный корпус, ауд. 201"
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-4 mb-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Страна
              </label>
              <input
                type="text"
                value={formData.country}
                onChange={(e) => setFormData({ ...formData, country: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Город
              </label>
              <input
                type="text"
                value={formData.city}
                onChange={(e) => setFormData({ ...formData, city: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <div className="flex space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 text-gray-700 bg-gray-200 rounded-md hover:bg-gray-300 transition-colors"
            >
              Отмена
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
            >
              Создать
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Компонент статистики
const StatsCard = ({ title, value, icon, color = "blue" }) => {
  const colorClasses = {
    blue: "bg-blue-50 text-blue-700 border-blue-200",
    green: "bg-green-50 text-green-700 border-green-200",
    yellow: "bg-yellow-50 text-yellow-700 border-yellow-200",
    red: "bg-red-50 text-red-700 border-red-200"
  };

  return (
    <div className={`p-4 rounded-lg border ${colorClasses[color]}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium opacity-75">{title}</p>
          <p className="text-2xl font-bold">{value}</p>
        </div>
        <div className="text-2xl">{icon}</div>
      </div>
    </div>
  );
};

// Основной компонент приложения
function App() {
  const [connections, setConnections] = useState([]);
  const [stats, setStats] = useState({});
  const [logs, setLogs] = useState([]);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [vncConnection, setVncConnection] = useState(null);
  const [fileManagerConnection, setFileManagerConnection] = useState(null);

  // Загрузка данных при монтировании компонента
  useEffect(() => {
    loadData();
    // Обновление данных каждые 30 секунд
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      const [connectionsRes, statsRes, logsRes] = await Promise.all([
        axios.get(`${API}/connections`),
        axios.get(`${API}/stats`),
        axios.get(`${API}/logs?limit=50`)
      ]);

      setConnections(connectionsRes.data);
      setStats(statsRes.data);
      setLogs(logsRes.data);
      setError(null);
    } catch (err) {
      console.error('Ошибка загрузки данных:', err);
      setError('Не удалось загрузить данные');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateConnection = async (formData) => {
    try {
      await axios.post(`${API}/connections`, formData);
      loadData(); // Перезагрузить данные
    } catch (err) {
      console.error('Ошибка создания соединения:', err);
      alert('Ошибка создания соединения');
    }
  };

  const handleGenerateInstaller = async (connectionId) => {
    try {
      const response = await axios.get(`${API}/generate-installer/${connectionId}`, {
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `vnc_installer_${connectionId.substring(0, 8)}.ps1`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      loadData(); // Обновить логи
    } catch (err) {
      console.error('Ошибка генерации установщика:', err);
      alert('Ошибка генерации установщика');
    }
  };

  const handleConnect = async (connectionId) => {
    try {
      const response = await axios.post(`${API}/connect/${connectionId}`);
      const connectionData = connections.find(c => c.id === connectionId);
      
      setVncConnection({
        ...connectionData,
        ...response.data
      });
    } catch (err) {
      console.error('Ошибка подключения к VNC:', err);
      alert('Ошибка подключения к VNC');
    }
  };

  const handleOpenFileManager = (connectionId) => {
    const connectionData = connections.find(c => c.id === connectionId);
    if (connectionData && connectionData.status === 'active') {
      setFileManagerConnection(connectionData);
    } else {
      alert('Соединение неактивно. Файловый менеджер доступен только для активных соединений.');
    }
  };

  const handleDeleteConnection = async (connectionId) => {
    if (!window.confirm('Вы уверены, что хотите удалить это соединение?')) {
      return;
    }

    try {
      await axios.delete(`${API}/connections/${connectionId}`);
      loadData(); // Перезагрузить данные
    } catch (err) {
      console.error('Ошибка удаления соединения:', err);
      alert('Ошибка удаления соединения');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Загрузка...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <p className="text-red-600 text-xl mb-4">❌ {error}</p>
          <button
            onClick={loadData}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
          >
            Попробовать снова
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Заголовок */}
      <div className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-gray-900">
                🖥️ VNC Management System
              </h1>
              <span className="ml-3 text-sm text-gray-500">
                Система управления удаленными подключениями
              </span>
            </div>
            <button
              onClick={() => setIsCreateModalOpen(true)}
              className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors font-medium"
            >
              ➕ Добавить компьютер
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Статистики */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <StatsCard
            title="Всего компьютеров"
            value={stats.total_connections || 0}
            icon="🖥️"
            color="blue"
          />
          <StatsCard
            title="Активные"
            value={stats.active_connections || 0}
            icon="🟢"
            color="green"
          />
          <StatsCard
            title="Неактивные"
            value={stats.inactive_connections || 0}
            icon="🔴"
            color="red"
          />
          <StatsCard
            title="Активность за 24ч"
            value={stats.recent_activity_24h || 0}
            icon="📊"
            color="yellow"
          />
        </div>

        {/* Список соединений */}
        <div className="mb-8">
          <h2 className="text-xl font-bold text-gray-900 mb-6">VNC Соединения</h2>
          
          {connections.length === 0 ? (
            <div className="text-center py-12 bg-white rounded-lg shadow-sm">
              <div className="text-6xl mb-4">🖥️</div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                Нет добавленных компьютеров
              </h3>
              <p className="text-gray-600 mb-6">
                Добавьте первый компьютер для удаленного управления
              </p>
              <button
                onClick={() => setIsCreateModalOpen(true)}
                className="bg-blue-600 text-white px-6 py-3 rounded-md hover:bg-blue-700 transition-colors font-medium"
              >
                ➕ Добавить компьютер
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {connections.map((connection) => (
                <ConnectionCard
                  key={connection.id}
                  connection={connection}
                  onGenerateInstaller={handleGenerateInstaller}
                  onConnect={handleConnect}
                  onDelete={handleDeleteConnection}
                  onFileManager={handleOpenFileManager}
                />
              ))}
            </div>
          )}
        </div>

        {/* Журнал активности */}
        {logs.length > 0 && (
          <div>
            <h2 className="text-xl font-bold text-gray-900 mb-6">Журнал активности</h2>
            <div className="bg-white rounded-lg shadow-sm overflow-hidden">
              <div className="max-h-96 overflow-y-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50 sticky top-0">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Время
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Действие
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Детали
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {logs.map((log) => (
                      <tr key={log.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {log.action}
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-500">
                          {log.details}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Модальное окно создания соединения */}
      <CreateConnectionModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onCreateConnection={handleCreateConnection}
      />
    </div>
  );
}

export default App;