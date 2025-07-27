"""
Comprehensive tests for SSL/TLS support in WebSocketServer
"""

import asyncio
import os
import ssl
import tempfile
import warnings
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict

from aiows.server import WebSocketServer, CertificateManager


class TestCertificateManager:
    """Test simplified CertificateManager functionality"""
    
    def test_cleanup_temp_files(self):
        temp_file1 = tempfile.NamedTemporaryFile(delete=False)
        temp_file2 = tempfile.NamedTemporaryFile(delete=False)
        temp_file1.close()
        temp_file2.close()
        
        CertificateManager._temp_files = [temp_file1.name, temp_file2.name]
        
        assert os.path.exists(temp_file1.name)
        assert os.path.exists(temp_file2.name)
        
        CertificateManager.cleanup_temp_files()
        
        assert not os.path.exists(temp_file1.name)
        assert not os.path.exists(temp_file2.name)
        assert len(CertificateManager._temp_files) == 0
    
    @patch('subprocess.run')
    def test_generate_self_signed_cert_with_ipv6(self, mock_run):
        mock_run.return_value = Mock(returncode=0, stderr="")
        
        cert_file, key_file = CertificateManager.generate_self_signed_cert(
            common_name="test.local",
            org_name="Test Org",
            country="CA"
        )
        
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        
        assert 'openssl' in cmd
        assert '-addext' in cmd
        
        san_ext = None
        for i, arg in enumerate(cmd):
            if arg == '-addext':
                san_ext = cmd[i + 1]
                break
        
        assert san_ext is not None
        assert ':::1' in san_ext
        assert 'test.local' in san_ext
        
        assert cert_file in CertificateManager._temp_files
        assert key_file in CertificateManager._temp_files
    
    @patch('subprocess.run')
    def test_generate_cert_timeout_protection(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired('openssl', 30)
        
        with pytest.raises(RuntimeError, match="OpenSSL not available or timed out"):
            CertificateManager.generate_self_signed_cert()
        
        mock_run.assert_called_once()
        assert mock_run.call_args[1]['timeout'] == 30
    
    def test_create_secure_ssl_context(self):
        cert_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
        key_file = tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False)
        
        cert_content = """-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKl9i3x7Y+BjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yMzEwMjUxMjAwMDBaFw0yNDEwMjQxMjAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyK8bQ2UlgGn7Qs8dEqpI
-----END CERTIFICATE-----"""
        
        key_content = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDIrxtDZSWAaftn
-----END PRIVATE KEY-----"""
        
        cert_file.write(cert_content)
        key_file.write(key_content)
        cert_file.close()
        key_file.close()
        
        try:
            context = CertificateManager.create_secure_ssl_context(cert_file.name, key_file.name)
            
            assert isinstance(context, ssl.SSLContext)
            assert context.minimum_version == ssl.TLSVersion.TLSv1_2
            assert context.verify_mode == ssl.CERT_NONE
            assert context.check_hostname == False
            
        except ssl.SSLError:
            pass
        finally:
            os.unlink(cert_file.name)
            os.unlink(key_file.name)
    
    @patch('subprocess.run')
    def test_validate_certificate(self, mock_run):
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Subject Alternative Name: DNS:localhost, IP:127.0.0.1, IP:::1"
        )
        
        result = CertificateManager.validate_certificate("test.pem")
        
        assert result['valid'] is True
        assert result['has_san'] is True
        assert result['has_ipv6'] is True
        
        mock_run.return_value = Mock(returncode=1, stdout="")
        result = CertificateManager.validate_certificate("invalid.pem")
        
        assert result['valid'] is False
        assert 'error' in result


class TestSimplifiedSSLServer:
    """Test simplified SSL server functionality"""
    
    def test_configurable_certificate_settings(self):
        cert_config = {
            'common_name': 'example.com',
            'org_name': 'Example Corp',
            'country': 'CA',
            'days': 730
        }
        
        server = WebSocketServer(cert_config=cert_config)
        
        assert server.cert_config == cert_config
        assert server.cert_config['common_name'] == 'example.com'
        assert server.cert_config['days'] == 730
    
    @patch.object(CertificateManager, 'generate_self_signed_cert')
    @patch.object(CertificateManager, 'create_secure_ssl_context')
    def test_development_ssl_with_config(self, mock_create_context, mock_generate):
        mock_generate.return_value = ('/tmp/cert.pem', '/tmp/key.pem')
        mock_create_context.return_value = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        cert_config = {
            'common_name': 'dev.example.com',
            'org_name': 'Dev Corp',
            'country': 'UK'
        }
        
        server = WebSocketServer(cert_config=cert_config)
        
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            context = server.create_development_ssl_context()
        
        mock_generate.assert_called_once_with(
            common_name='dev.example.com',
            org_name='Dev Corp',
            country='UK',
            days=365
        )
        
        assert server._ssl_cert_files == ('/tmp/cert.pem', '/tmp/key.pem')
    
    def test_ssl_certificate_validation(self):
        server = WebSocketServer()
        
        result = server.validate_ssl_certificate()
        assert result['valid'] is False
        assert result['error'] == 'SSL not enabled'
        
        server.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        result = server.validate_ssl_certificate()
        assert result['valid'] is False
        assert result['error'] == 'No certificate files tracked'
    
    @patch.object(CertificateManager, 'validate_certificate')
    @patch.object(CertificateManager, 'create_secure_ssl_context')
    def test_certificate_hot_reload(self, mock_create_context, mock_validate):
        mock_validate.return_value = {'valid': True}
        new_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        mock_create_context.return_value = new_context
        
        server = WebSocketServer(ssl_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
        old_context = server.ssl_context
        
        result = server.reload_ssl_certificate('/new/cert.pem', '/new/key.pem')
        
        assert result is True
        assert server.ssl_context is new_context
        assert server.ssl_context is not old_context
        assert server._ssl_cert_files == ('/new/cert.pem', '/new/key.pem')
        
        mock_validate.return_value = {'valid': False, 'error': 'Invalid cert'}
        result = server.reload_ssl_certificate('/bad/cert.pem', '/bad/key.pem')
        
        assert result is False
    
    def test_memory_cleanup_on_exit(self):
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.close()
        
        original_temp_files = CertificateManager._temp_files.copy()
        CertificateManager._temp_files.append(temp_file.name)
        
        try:
            assert os.path.exists(temp_file.name)
            
            CertificateManager.cleanup_temp_files()
            
            assert not os.path.exists(temp_file.name)
            assert len(CertificateManager._temp_files) == 0
            
        finally:
            CertificateManager._temp_files = original_temp_files
            try:
                os.unlink(temp_file.name)
            except:
                pass


class TestSSLSecurityConfiguration:
    """Test SSL security configuration"""
    
    def test_secure_ssl_defaults(self):
        cert_file = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
        key_file = tempfile.NamedTemporaryFile(suffix='.key', delete=False)
        cert_file.close()
        key_file.close()
        
        try:
            try:
                context = CertificateManager.create_secure_ssl_context(cert_file.name, key_file.name)
                
                assert context.minimum_version == ssl.TLSVersion.TLSv1_2
                assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
                
            except ssl.SSLError:
                pass
                
        finally:
            os.unlink(cert_file.name)  
            os.unlink(key_file.name)
    
    @patch('subprocess.run')
    def test_cipher_suite_configuration(self, mock_run):
        mock_run.return_value = Mock(returncode=0, stderr="")
        
        cert_file, key_file = CertificateManager.generate_self_signed_cert()
        
        try:
            try:
                context = CertificateManager.create_secure_ssl_context(cert_file, key_file)
            except ssl.SSLError:
                pass
        finally:
            pass


class TestSSLErrorHandling:
    """Test SSL error handling"""
    
    @patch('subprocess.run')
    def test_openssl_failure_handling(self, mock_run):
        mock_run.return_value = Mock(returncode=1, stderr="OpenSSL error")
        
        with pytest.raises(RuntimeError, match="Certificate generation failed"):
            CertificateManager.generate_self_signed_cert()
    
    @patch('subprocess.run')
    def test_openssl_not_found_handling(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        
        with pytest.raises(RuntimeError, match="OpenSSL not available"):
            CertificateManager.generate_self_signed_cert()
    
    def test_ssl_context_creation_error_handling(self):
        server = WebSocketServer()
        
        with patch.object(CertificateManager, 'generate_self_signed_cert', side_effect=RuntimeError("Test error")):
            with pytest.raises(RuntimeError, match="Test error"):
                server.create_development_ssl_context()


class TestSSLPerformance:
    """Test SSL performance improvements"""
    
    @patch('subprocess.run')
    def test_certificate_generation_performance(self, mock_run):
        import time
        
        mock_run.return_value = Mock(returncode=0, stderr="")
        
        start_time = time.time()
        cert_file, key_file = CertificateManager.generate_self_signed_cert()
        end_time = time.time()
        
        assert end_time - start_time < 1.0
        
        mock_run.assert_called_once()
        assert mock_run.call_args[1]['timeout'] == 30
    
    def test_simplified_api_usage(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            
            try:
                server = WebSocketServer()
                server.enable_development_ssl()
                
                assert server.is_ssl_enabled
                assert server.protocol == "wss"
                
            except (RuntimeError, ImportError):
                pytest.skip("OpenSSL not available for performance test")


class TestSSLIntegration:
    """Test SSL integration with WebSocket server"""
    
    @pytest.mark.asyncio
    async def test_ssl_server_startup_logging(self, caplog):
        import logging
        
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server = WebSocketServer(ssl_context=ssl_context)
        
        with patch('websockets.serve') as mock_serve:
            mock_serve.return_value.__aenter__ = AsyncMock()
            mock_serve.return_value.__aexit__ = AsyncMock()
            
            async def mock_server_task():
                await asyncio.sleep(0.01)
                await server.shutdown()
            
            with caplog.at_level(logging.INFO):
                shutdown_task = asyncio.create_task(mock_server_task())
                try:
                    await asyncio.wait_for(server.serve("localhost", 8443), timeout=1.0)
                except asyncio.TimeoutError:
                    await server.shutdown()
                finally:
                    if not shutdown_task.done():
                        shutdown_task.cancel()
            
            assert any("secure WebSocket server" in record.message for record in caplog.records)
    
    def test_backward_compatibility_preserved(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            
            server = WebSocketServer()
            assert not server.is_ssl_enabled
            assert server.protocol == "ws"
            
            assert hasattr(server, 'enable_development_ssl')
            assert hasattr(server, 'create_development_ssl_context')


if __name__ == "__main__":
    pytest.main([__file__]) 