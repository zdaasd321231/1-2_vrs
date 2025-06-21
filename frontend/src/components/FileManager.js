import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const FileManager = ({ connection, onClose }) => {
  const [files, setFiles] = useState([]);
  const [currentPath, setCurrentPath] = useState('/');
  const [loading, setLoading] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [transfers, setTransfers] = useState([]);
  const fileInputRef = useRef(null);

  useEffect(() => {
    if (connection) {
      loadFiles();
      loadTransfers();
    }
  }, [connection, currentPath]);

  const loadFiles = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${API}/files/${connection.id}?path=${encodeURIComponent(currentPath)}`);
      setFiles(response.data.files);
      setCurrentPath(response.data.current_path);
    } catch (error) {
      console.error('Error loading files:', error);
      alert('Ошибка загрузки файлов');
    } finally {
      setLoading(false);
    }
  };

  const loadTransfers = async () => {
    try {
      const response = await axios.get(`${API}/files/${connection.id}/transfers`);
      setTransfers(response.data);
    } catch (error) {
      console.error('Error loading transfers:', error);
    }
  };

  const handleFileSelect = (file) => {
    if (selectedFiles.includes(file.name)) {
      setSelectedFiles(selectedFiles.filter(name => name !== file.name));
    } else {
      setSelectedFiles([...selectedFiles, file.name]);
    }
  };

  const handleDoubleClick = (file) => {
    if (file.type === 'directory') {
      setCurrentPath(file.path);
      setSelectedFiles([]);
    } else {
      downloadFile(file);
    }
  };

  const downloadFile = async (file) => {
    try {
      const response = await axios.get(`${API}/files/${connection.id}/download?file_path=${encodeURIComponent(file.path)}`, {
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', file.name);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      loadTransfers(); // Обновить историю передач
    } catch (error) {
      console.error('Error downloading file:', error);
      alert('Ошибка скачивания файла');
    }
  };

  const uploadFiles = async (files) => {
    if (!files || files.length === 0) return;

    setIsUploading(true);
    setUploadProgress(0);

    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const formData = new FormData();
        formData.append('file', file);
        formData.append('remote_path', currentPath);

        const response = await axios.post(`${API}/files/${connection.id}/upload`, formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
          onUploadProgress: (progressEvent) => {
            const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            setUploadProgress(((i + progress / 100) / files.length) * 100);
          }
        });

        console.log('File uploaded:', response.data);
      }

      loadFiles(); // Обновить список файлов
      loadTransfers(); // Обновить историю передач
      alert(`Успешно загружено ${files.length} файл(ов)`);
    } catch (error) {
      console.error('Error uploading files:', error);
      alert('Ошибка загрузки файлов');
    } finally {
      setIsUploading(false);
      setUploadProgress(0);
    }
  };

  const handleFileUpload = (event) => {
    const files = Array.from(event.target.files);
    uploadFiles(files);
    event.target.value = ''; // Сбросить input
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const getFileIcon = (file) => {
    if (file.type === 'directory') return '📁';
    
    const ext = file.name.split('.').pop()?.toLowerCase();
    switch (ext) {
      case 'pdf': return '📄';
      case 'doc':
      case 'docx': return '📝';
      case 'xls':
      case 'xlsx': return '📊';
      case 'jpg':
      case 'jpeg':
      case 'png':
      case 'gif': return '🖼️';
      case 'mp4':
      case 'avi':
      case 'mov': return '🎬';
      case 'mp3':
      case 'wav': return '🎵';
      case 'zip':
      case 'rar':
      case '7z': return '📦';
      case 'txt': return '📄';
      default: return '📄';
    }
  };

  const navigateUp = () => {
    if (currentPath !== '/') {
      const parentPath = currentPath.split('/').slice(0, -1).join('/') || '/';
      setCurrentPath(parentPath);
    }
  };

  return (
    <div className="fixed inset-0 bg-white z-50 flex flex-col">
      {/* Заголовок */}
      <div className="bg-blue-600 text-white p-4 flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold">📁 File Manager - {connection.name}</h2>
          <p className="text-sm text-blue-100">
            {connection.ip_address} | Path: {currentPath}
          </p>
        </div>
        <button
          onClick={onClose}
          className="bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700 transition-colors"
        >
          ✕ Close
        </button>
      </div>

      <div className="flex-1 flex">
        {/* Основная панель файлов */}
        <div className="flex-1 flex flex-col">
          {/* Панель навигации */}
          <div className="bg-gray-100 p-4 border-b flex justify-between items-center">
            <div className="flex space-x-2">
              <button
                onClick={navigateUp}
                disabled={currentPath === '/'}
                className={`px-3 py-1 rounded ${currentPath === '/' 
                  ? 'bg-gray-300 text-gray-500 cursor-not-allowed' 
                  : 'bg-gray-600 text-white hover:bg-gray-700'
                } transition-colors`}
              >
                ⬆️ Up
              </button>
              <button
                onClick={loadFiles}
                className="bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700 transition-colors"
              >
                🔄 Refresh
              </button>
            </div>
            
            <div className="flex space-x-2">
              <input
                type="file"
                multiple
                onChange={handleFileUpload}
                ref={fileInputRef}
                className="hidden"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={isUploading}
                className="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700 transition-colors disabled:bg-gray-400"
              >
                {isUploading ? `📤 Uploading... ${Math.round(uploadProgress)}%` : '📤 Upload Files'}
              </button>
              {selectedFiles.length > 0 && (
                <button
                  onClick={() => selectedFiles.forEach(fileName => {
                    const file = files.find(f => f.name === fileName);
                    if (file && file.type === 'file') downloadFile(file);
                  })}
                  className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition-colors"
                >
                  📥 Download Selected ({selectedFiles.length})
                </button>
              )}
            </div>
          </div>

          {/* Список файлов */}
          <div className="flex-1 overflow-auto">
            {loading ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-600 mx-auto mb-4"></div>
                  <p>Loading files...</p>
                </div>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-50 sticky top-0">
                  <tr>
                    <th className="px-4 py-2 text-left">
                      <input
                        type="checkbox"
                        checked={selectedFiles.length === files.filter(f => f.type === 'file').length}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedFiles(files.filter(f => f.type === 'file').map(f => f.name));
                          } else {
                            setSelectedFiles([]);
                          }
                        }}
                      />
                    </th>
                    <th className="px-4 py-2 text-left">Name</th>
                    <th className="px-4 py-2 text-left">Size</th>
                    <th className="px-4 py-2 text-left">Modified</th>
                    <th className="px-4 py-2 text-left">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {files.map((file, index) => (
                    <tr
                      key={index}
                      className={`border-b hover:bg-gray-50 cursor-pointer ${
                        selectedFiles.includes(file.name) ? 'bg-blue-50' : ''
                      }`}
                      onDoubleClick={() => handleDoubleClick(file)}
                    >
                      <td className="px-4 py-2">
                        {file.type === 'file' && (
                          <input
                            type="checkbox"
                            checked={selectedFiles.includes(file.name)}
                            onChange={() => handleFileSelect(file)}
                            onClick={(e) => e.stopPropagation()}
                          />
                        )}
                      </td>
                      <td className="px-4 py-2">
                        <div className="flex items-center space-x-2">
                          <span className="text-xl">{getFileIcon(file)}</span>
                          <span className={file.type === 'directory' ? 'font-bold text-blue-600' : ''}>
                            {file.name}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-2 text-gray-600">
                        {file.type === 'directory' ? '-' : formatFileSize(file.size)}
                      </td>
                      <td className="px-4 py-2 text-gray-600">
                        {formatDate(file.modified)}
                      </td>
                      <td className="px-4 py-2">
                        {file.type === 'file' && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              downloadFile(file);
                            }}
                            className="bg-blue-600 text-white px-2 py-1 rounded text-sm hover:bg-blue-700 transition-colors"
                          >
                            📥 Download
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Боковая панель с историей передач */}
        <div className="w-80 bg-gray-50 border-l flex flex-col">
          <div className="p-4 border-b">
            <h3 className="font-bold text-lg">📊 File Transfers</h3>
          </div>
          
          <div className="flex-1 overflow-auto">
            {transfers.length === 0 ? (
              <div className="p-4 text-center text-gray-500">
                No file transfers yet
              </div>
            ) : (
              <div className="p-4 space-y-3">
                {transfers.map((transfer) => (
                  <div key={transfer.id} className="bg-white p-3 rounded shadow-sm border">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-sm">{transfer.filename}</span>
                      <span className={`px-2 py-1 rounded text-xs ${
                        transfer.transfer_type === 'upload' 
                          ? 'bg-green-100 text-green-800' 
                          : 'bg-blue-100 text-blue-800'
                      }`}>
                        {transfer.transfer_type === 'upload' ? '📤 Upload' : '📥 Download'}
                      </span>
                    </div>
                    <div className="text-xs text-gray-500">
                      <div>Size: {formatFileSize(transfer.file_size)}</div>
                      <div>Date: {formatDate(transfer.timestamp)}</div>
                      <div>Checksum: {transfer.checksum.substring(0, 8)}...</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
          
          <div className="p-4 border-t">
            <button
              onClick={loadTransfers}
              className="w-full bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition-colors"
            >
              🔄 Refresh Transfers
            </button>
          </div>
        </div>
      </div>

      {/* Progress bar для загрузки */}
      {isUploading && (
        <div className="fixed bottom-0 left-0 right-0 bg-white border-t p-4">
          <div className="flex items-center space-x-4">
            <span className="text-sm font-medium">Uploading files...</span>
            <div className="flex-1 bg-gray-200 rounded-full h-2">
              <div
                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${uploadProgress}%` }}
              ></div>
            </div>
            <span className="text-sm text-gray-600">{Math.round(uploadProgress)}%</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default FileManager;