"""
Performance Optimizer - Optimizes performance for large wordlists and long operations
Implements memory management, caching, and resource optimization strategies

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import os
import sys
import gc
import psutil
import threading
import time
import mmap
from typing import Dict, Any, List, Optional, Iterator, Callable
from pathlib import Path
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing as mp

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent.parent))
from core.logger import get_logger
from utils.common import format_bytes


@dataclass
class PerformanceMetrics:
    """Performance metrics tracking"""
    memory_usage: int  # bytes
    cpu_usage: float   # percentage
    disk_io: Dict[str, int]  # read/write bytes
    network_io: Dict[str, int]  # sent/received bytes
    operation_time: float  # seconds
    throughput: float  # operations per second


class MemoryManager:
    """Manages memory usage for large operations"""
    
    def __init__(self, max_memory_mb: int = 1024):
        self.logger = get_logger("memory_manager")
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.current_usage = 0
        self.memory_pools = {}
        self.gc_threshold = 0.8  # Trigger GC at 80% memory usage
        
    def get_memory_usage(self) -> Dict[str, Any]:
        """Get current memory usage statistics"""
        process = psutil.Process()
        memory_info = process.memory_info()
        
        return {
            'rss': memory_info.rss,  # Resident Set Size
            'vms': memory_info.vms,  # Virtual Memory Size
            'percent': process.memory_percent(),
            'available': psutil.virtual_memory().available,
            'total': psutil.virtual_memory().total
        }
    
    def check_memory_pressure(self) -> bool:
        """Check if system is under memory pressure"""
        memory_info = self.get_memory_usage()
        return memory_info['percent'] > 80.0
    
    def optimize_for_large_wordlist(self, wordlist_size: int) -> Dict[str, Any]:
        """Optimize memory settings for large wordlist processing"""
        memory_info = self.get_memory_usage()
        available_mb = memory_info['available'] // (1024 * 1024)
        
        # Calculate optimal chunk size based on available memory
        if wordlist_size > 10_000_000:  # 10M+ passwords
            chunk_size = min(100_000, available_mb * 100)  # 100 passwords per MB
            use_memory_mapping = True
            enable_streaming = True
        elif wordlist_size > 1_000_000:  # 1M+ passwords
            chunk_size = min(500_000, available_mb * 500)
            use_memory_mapping = True
            enable_streaming = False
        else:
            chunk_size = wordlist_size
            use_memory_mapping = False
            enable_streaming = False
        
        optimization_config = {
            'chunk_size': chunk_size,
            'use_memory_mapping': use_memory_mapping,
            'enable_streaming': enable_streaming,
            'gc_frequency': max(1, chunk_size // 10000),  # GC every N chunks
            'buffer_size': min(8192, available_mb * 8)  # 8 bytes per MB available
        }
        
        self.logger.info(f"Memory optimization for {wordlist_size:,} passwords: {optimization_config}")
        return optimization_config
    
    def create_memory_mapped_file(self, file_path: str) -> Optional[mmap.mmap]:
        """Create memory-mapped file for efficient large file access"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Memory map the file for efficient access
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                return mm
        except Exception as e:
            self.logger.error(f"Failed to create memory map for {file_path}: {e}")
            return None
    
    def trigger_garbage_collection(self) -> Dict[str, int]:
        """Trigger garbage collection and return statistics"""
        before_memory = self.get_memory_usage()
        
        # Force garbage collection
        collected = gc.collect()
        
        after_memory = self.get_memory_usage()
        freed_bytes = before_memory['rss'] - after_memory['rss']
        
        gc_stats = {
            'objects_collected': collected,
            'memory_freed_bytes': max(0, freed_bytes),
            'memory_freed_mb': max(0, freed_bytes) // (1024 * 1024)
        }
        
        self.logger.debug(f"Garbage collection: {gc_stats}")
        return gc_stats


class WordlistOptimizer:
    """Optimizes wordlist processing for performance"""
    
    def __init__(self, memory_manager: MemoryManager):
        self.logger = get_logger("wordlist_optimizer")
        self.memory_manager = memory_manager
        
    def create_optimized_wordlist_iterator(self, wordlist_path: str, 
                                         chunk_size: int = 100000) -> Iterator[List[str]]:
        """Create memory-efficient iterator for large wordlists"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                chunk = []
                for line in f:
                    password = line.strip()
                    if password and not password.startswith('#'):
                        chunk.append(password)
                        
                        if len(chunk) >= chunk_size:
                            yield chunk
                            chunk = []
                            
                            # Check memory pressure and trigger GC if needed
                            if self.memory_manager.check_memory_pressure():
                                self.memory_manager.trigger_garbage_collection()
                
                # Yield remaining passwords
                if chunk:
                    yield chunk
                    
        except Exception as e:
            self.logger.error(f"Error creating wordlist iterator: {e}")
            yield []
    
    def preprocess_wordlist_for_cracking(self, wordlist_path: str, 
                                       output_path: str) -> Dict[str, Any]:
        """Preprocess wordlist for optimal cracking performance"""
        try:
            self.logger.info(f"Preprocessing wordlist: {wordlist_path}")
            
            # Statistics
            stats = {
                'original_count': 0,
                'processed_count': 0,
                'duplicates_removed': 0,
                'invalid_removed': 0,
                'size_reduction_percent': 0
            }
            
            seen_passwords = set()
            
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as infile, \
                 open(output_path, 'w', encoding='utf-8') as outfile:
                
                for line in infile:
                    stats['original_count'] += 1
                    password = line.strip()
                    
                    # Skip empty lines and comments
                    if not password or password.startswith('#'):
                        continue
                    
                    # Validate password (8-63 characters for WPA/WPA2)
                    if len(password) < 8 or len(password) > 63:
                        stats['invalid_removed'] += 1
                        continue
                    
                    # Check for duplicates
                    if password in seen_passwords:
                        stats['duplicates_removed'] += 1
                        continue
                    
                    seen_passwords.add(password)
                    outfile.write(f"{password}\n")
                    stats['processed_count'] += 1
                    
                    # Periodic memory cleanup for very large wordlists
                    if stats['processed_count'] % 100000 == 0:
                        if self.memory_manager.check_memory_pressure():
                            # Clear seen_passwords set periodically for huge wordlists
                            if len(seen_passwords) > 1000000:
                                seen_passwords.clear()
                                gc.collect()
            
            # Calculate size reduction
            if stats['original_count'] > 0:
                stats['size_reduction_percent'] = round(
                    ((stats['original_count'] - stats['processed_count']) / stats['original_count']) * 100, 2
                )
            
            self.logger.info(f"Wordlist preprocessing complete: {stats}")
            return stats
            
        except Exception as e:
            self.logger.error(f"Error preprocessing wordlist: {e}")
            return {'error': str(e)}
    
    def split_wordlist_for_parallel_processing(self, wordlist_path: str, 
                                             num_splits: int) -> List[str]:
        """Split large wordlist into smaller files for parallel processing"""
        try:
            self.logger.info(f"Splitting wordlist into {num_splits} parts")
            
            # Count total lines first
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                total_lines = sum(1 for line in f if line.strip() and not line.startswith('#'))
            
            lines_per_split = max(1, total_lines // num_splits)
            split_files = []
            
            base_path = Path(wordlist_path)
            
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as infile:
                current_split = 0
                current_line_count = 0
                current_file = None
                
                for line in infile:
                    password = line.strip()
                    if not password or password.startswith('#'):
                        continue
                    
                    # Open new split file if needed
                    if current_file is None or current_line_count >= lines_per_split:
                        if current_file:
                            current_file.close()
                        
                        split_filename = f"{base_path.stem}_split_{current_split}.txt"
                        split_path = base_path.parent / split_filename
                        split_files.append(str(split_path))
                        
                        current_file = open(split_path, 'w', encoding='utf-8')
                        current_split += 1
                        current_line_count = 0
                    
                    current_file.write(f"{password}\n")
                    current_line_count += 1
                
                if current_file:
                    current_file.close()
            
            self.logger.info(f"Created {len(split_files)} split files")
            return split_files
            
        except Exception as e:
            self.logger.error(f"Error splitting wordlist: {e}")
            return []


class ProcessOptimizer:
    """Optimizes process execution for long-running operations"""
    
    def __init__(self):
        self.logger = get_logger("process_optimizer")
        self.cpu_count = mp.cpu_count()
        self.optimal_workers = max(1, self.cpu_count - 1)  # Leave one CPU free
        
    def get_optimal_thread_count(self, operation_type: str) -> int:
        """Get optimal thread count for different operation types"""
        if operation_type == 'io_bound':
            # IO-bound operations can use more threads
            return min(self.cpu_count * 2, 16)
        elif operation_type == 'cpu_bound':
            # CPU-bound operations should match CPU count
            return self.cpu_count
        elif operation_type == 'mixed':
            # Mixed operations use moderate threading
            return max(2, self.cpu_count // 2)
        else:
            return self.optimal_workers
    
    def optimize_process_priority(self, process_type: str) -> bool:
        """Optimize process priority for different operation types"""
        try:
            current_process = psutil.Process()
            
            if process_type == 'background':
                # Lower priority for background operations
                current_process.nice(10)
            elif process_type == 'interactive':
                # Normal priority for interactive operations
                current_process.nice(0)
            elif process_type == 'critical':
                # Higher priority for critical operations
                current_process.nice(-5)
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Could not adjust process priority: {e}")
            return False
    
    def create_optimized_executor(self, operation_type: str, 
                                max_workers: Optional[int] = None) -> ThreadPoolExecutor:
        """Create optimized thread pool executor"""
        if max_workers is None:
            max_workers = self.get_optimal_thread_count(operation_type)
        
        return ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix=f"{operation_type}_worker"
        )


class CacheManager:
    """Manages caching for frequently accessed data"""
    
    def __init__(self, max_cache_size_mb: int = 256):
        self.logger = get_logger("cache_manager")
        self.max_cache_size = max_cache_size_mb * 1024 * 1024
        self.cache = {}
        self.cache_stats = {'hits': 0, 'misses': 0, 'evictions': 0}
        self.access_times = {}
        
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        if key in self.cache:
            self.cache_stats['hits'] += 1
            self.access_times[key] = time.time()
            return self.cache[key]
        else:
            self.cache_stats['misses'] += 1
            return None
    
    def put(self, key: str, value: Any, size_bytes: Optional[int] = None) -> bool:
        """Put item in cache with size-based eviction"""
        try:
            if size_bytes is None:
                size_bytes = sys.getsizeof(value)
            
            # Check if we need to evict items
            while self._get_cache_size() + size_bytes > self.max_cache_size:
                if not self._evict_lru_item():
                    return False  # Could not evict enough space
            
            self.cache[key] = value
            self.access_times[key] = time.time()
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding to cache: {e}")
            return False
    
    def _get_cache_size(self) -> int:
        """Get approximate cache size in bytes"""
        return sum(sys.getsizeof(value) for value in self.cache.values())
    
    def _evict_lru_item(self) -> bool:
        """Evict least recently used item"""
        if not self.cache:
            return False
        
        # Find least recently used item
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        
        # Remove from cache
        del self.cache[lru_key]
        del self.access_times[lru_key]
        self.cache_stats['evictions'] += 1
        
        return True
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics"""
        total_requests = self.cache_stats['hits'] + self.cache_stats['misses']
        hit_rate = (self.cache_stats['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'hits': self.cache_stats['hits'],
            'misses': self.cache_stats['misses'],
            'evictions': self.cache_stats['evictions'],
            'hit_rate_percent': round(hit_rate, 2),
            'cache_size_bytes': self._get_cache_size(),
            'cache_size_mb': self._get_cache_size() / (1024 * 1024),
            'items_count': len(self.cache)
        }


class PerformanceOptimizer:
    """Main performance optimizer coordinating all optimization strategies"""
    
    def __init__(self):
        self.logger = get_logger("performance_optimizer")
        self.memory_manager = MemoryManager()
        self.wordlist_optimizer = WordlistOptimizer(self.memory_manager)
        self.process_optimizer = ProcessOptimizer()
        self.cache_manager = CacheManager()
        
        # Performance monitoring
        self.metrics_history = []
        self.monitoring_active = False
        self.monitoring_thread = None
    
    def optimize_for_operation(self, operation_type: str, 
                             context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize system for specific operation type"""
        optimization_config = {
            'memory_config': {},
            'process_config': {},
            'cache_config': {},
            'recommendations': []
        }
        
        try:
            if operation_type == 'large_wordlist_crack':
                wordlist_size = context.get('wordlist_size', 0)
                
                # Memory optimization
                memory_config = self.memory_manager.optimize_for_large_wordlist(wordlist_size)
                optimization_config['memory_config'] = memory_config
                
                # Process optimization
                self.process_optimizer.optimize_process_priority('background')
                optimization_config['process_config'] = {
                    'priority': 'background',
                    'optimal_threads': self.process_optimizer.get_optimal_thread_count('cpu_bound')
                }
                
                # Recommendations
                if wordlist_size > 10_000_000:
                    optimization_config['recommendations'].extend([
                        'Consider splitting wordlist for parallel processing',
                        'Monitor system memory usage during operation',
                        'Use SSD storage for better I/O performance'
                    ])
            
            elif operation_type == 'network_scan':
                # Optimize for I/O bound operations
                optimization_config['process_config'] = {
                    'priority': 'interactive',
                    'optimal_threads': self.process_optimizer.get_optimal_thread_count('io_bound')
                }
                
                # Cache network scan results
                optimization_config['cache_config'] = {
                    'cache_scan_results': True,
                    'cache_duration_minutes': 5
                }
            
            elif operation_type == 'packet_capture':
                # Optimize for real-time operations
                self.process_optimizer.optimize_process_priority('critical')
                optimization_config['process_config'] = {
                    'priority': 'critical',
                    'buffer_size': 'large'
                }
                
                optimization_config['recommendations'].extend([
                    'Ensure sufficient disk space for capture files',
                    'Close unnecessary applications to free resources',
                    'Use wired connection for management interface'
                ])
            
            self.logger.info(f"Optimization configured for {operation_type}: {optimization_config}")
            return optimization_config
            
        except Exception as e:
            self.logger.error(f"Error optimizing for {operation_type}: {e}")
            return optimization_config
    
    def start_performance_monitoring(self, interval_seconds: int = 30) -> None:
        """Start background performance monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._performance_monitoring_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self.monitoring_thread.start()
        self.logger.info("Performance monitoring started")
    
    def stop_performance_monitoring(self) -> None:
        """Stop performance monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        self.logger.info("Performance monitoring stopped")
    
    def _performance_monitoring_loop(self, interval_seconds: int) -> None:
        """Background performance monitoring loop"""
        while self.monitoring_active:
            try:
                metrics = self._collect_performance_metrics()
                self.metrics_history.append(metrics)
                
                # Keep only last 100 measurements
                if len(self.metrics_history) > 100:
                    self.metrics_history.pop(0)
                
                # Check for performance issues
                self._check_performance_alerts(metrics)
                
                time.sleep(interval_seconds)
                
            except Exception as e:
                self.logger.error(f"Error in performance monitoring: {e}")
                time.sleep(interval_seconds)
    
    def _collect_performance_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        process = psutil.Process()
        
        # Memory metrics
        memory_info = process.memory_info()
        
        # CPU metrics
        cpu_percent = process.cpu_percent()
        
        # I/O metrics
        try:
            io_counters = process.io_counters()
            disk_io = {
                'read_bytes': io_counters.read_bytes,
                'write_bytes': io_counters.write_bytes
            }
        except:
            disk_io = {'read_bytes': 0, 'write_bytes': 0}
        
        return PerformanceMetrics(
            memory_usage=memory_info.rss,
            cpu_usage=cpu_percent,
            disk_io=disk_io,
            network_io={'sent': 0, 'received': 0},  # Would implement if needed
            operation_time=time.time(),
            throughput=0.0  # Would calculate based on operation
        )
    
    def _check_performance_alerts(self, metrics: PerformanceMetrics) -> None:
        """Check for performance issues and log alerts"""
        # Memory usage alert
        if metrics.memory_usage > 2 * 1024 * 1024 * 1024:  # 2GB
            self.logger.warning(f"High memory usage: {format_bytes(metrics.memory_usage)}")
        
        # CPU usage alert
        if metrics.cpu_usage > 90.0:
            self.logger.warning(f"High CPU usage: {metrics.cpu_usage:.1f}%")
        
        # Trigger garbage collection if memory pressure detected
        if self.memory_manager.check_memory_pressure():
            self.memory_manager.trigger_garbage_collection()
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        if not self.metrics_history:
            return {'error': 'No performance data available'}
        
        # Calculate averages
        avg_memory = sum(m.memory_usage for m in self.metrics_history) / len(self.metrics_history)
        avg_cpu = sum(m.cpu_usage for m in self.metrics_history) / len(self.metrics_history)
        
        # Find peaks
        peak_memory = max(m.memory_usage for m in self.metrics_history)
        peak_cpu = max(m.cpu_usage for m in self.metrics_history)
        
        report = {
            'monitoring_duration_minutes': len(self.metrics_history) * 0.5,  # 30-second intervals
            'average_memory_usage': format_bytes(int(avg_memory)),
            'peak_memory_usage': format_bytes(peak_memory),
            'average_cpu_usage_percent': round(avg_cpu, 2),
            'peak_cpu_usage_percent': round(peak_cpu, 2),
            'cache_stats': self.cache_manager.get_cache_stats(),
            'memory_manager_stats': self.memory_manager.get_memory_usage(),
            'recommendations': self._generate_performance_recommendations()
        }
        
        return report
    
    def _generate_performance_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations"""
        recommendations = []
        
        if not self.metrics_history:
            return recommendations
        
        avg_memory = sum(m.memory_usage for m in self.metrics_history) / len(self.metrics_history)
        avg_cpu = sum(m.cpu_usage for m in self.metrics_history) / len(self.metrics_history)
        
        # Memory recommendations
        if avg_memory > 1024 * 1024 * 1024:  # 1GB
            recommendations.append("Consider increasing system RAM or reducing wordlist size")
        
        # CPU recommendations
        if avg_cpu > 80.0:
            recommendations.append("High CPU usage detected - consider reducing concurrent operations")
        
        # Cache recommendations
        cache_stats = self.cache_manager.get_cache_stats()
        if cache_stats['hit_rate_percent'] < 50:
            recommendations.append("Low cache hit rate - consider increasing cache size")
        
        return recommendations
    
    def cleanup_resources(self) -> None:
        """Clean up performance optimizer resources"""
        try:
            self.stop_performance_monitoring()
            self.memory_manager.trigger_garbage_collection()
            self.cache_manager.cache.clear()
            self.logger.info("Performance optimizer resources cleaned up")
        except Exception as e:
            self.logger.error(f"Error cleaning up performance optimizer: {e}")


# Global performance optimizer instance
_global_performance_optimizer = None


def get_performance_optimizer() -> PerformanceOptimizer:
    """Get the global performance optimizer instance"""
    global _global_performance_optimizer
    if _global_performance_optimizer is None:
        _global_performance_optimizer = PerformanceOptimizer()
    return _global_performance_optimizer