cmake_minimum_required(VERSION 3.5)
project(UdpQueue)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS -pthread)

add_executable(UdpQueue
        udp/UdpReceiver.cxx
        udp/UdpReceiver.h
        udp/UdpSender.cxx
        udp/UdpSender.h
        Utilities/spdlog/contrib/sinks/step_file_sink.h
        Utilities/spdlog/details/async_log_helper.h
        Utilities/spdlog/details/async_logger_impl.h
        Utilities/spdlog/details/file_helper.h
        Utilities/spdlog/details/log_msg.h
        Utilities/spdlog/details/logger_impl.h
        Utilities/spdlog/details/mpmc_blocking_q.h
        Utilities/spdlog/details/null_mutex.h
        Utilities/spdlog/details/os.h
        Utilities/spdlog/details/pattern_formatter_impl.h
        Utilities/spdlog/details/registry.h
        Utilities/spdlog/details/spdlog_impl.h
        Utilities/spdlog/fmt/bundled/format.cc
        Utilities/spdlog/fmt/bundled/format.h
        Utilities/spdlog/fmt/bundled/ostream.cc
        Utilities/spdlog/fmt/bundled/ostream.h
        Utilities/spdlog/fmt/bundled/posix.cc
        Utilities/spdlog/fmt/bundled/posix.h
        Utilities/spdlog/fmt/bundled/printf.cc
        Utilities/spdlog/fmt/bundled/printf.h
        Utilities/spdlog/fmt/bundled/time.h
        Utilities/spdlog/fmt/fmt.h
        Utilities/spdlog/fmt/ostr.h
        Utilities/spdlog/sinks/android_sink.h
        Utilities/spdlog/sinks/ansicolor_sink.h
        Utilities/spdlog/sinks/base_sink.h
        Utilities/spdlog/sinks/dist_sink.h
        Utilities/spdlog/sinks/file_sinks.h
        Utilities/spdlog/sinks/msvc_sink.h
        Utilities/spdlog/sinks/null_sink.h
        Utilities/spdlog/sinks/ostream_sink.h
        Utilities/spdlog/sinks/sink.h
        Utilities/spdlog/sinks/stdout_sinks.h
        Utilities/spdlog/sinks/syslog_sink.h
        Utilities/spdlog/sinks/wincolor_sink.h
        Utilities/spdlog/sinks/windebug_sink.h
        Utilities/spdlog/async_logger.h
        Utilities/spdlog/common.h
        Utilities/spdlog/formatter.h
        Utilities/spdlog/logger.h
        Utilities/spdlog/spdlog.h
        Utilities/spdlog/tweakme.h
        Utilities/Thread.cpp
        Utilities/Thread.h
        Utilities/ThreadTest.cpp
        Utilities/ThreadTest.h
        Utilities/Utility.h
        main.cxx
        NetworkReceiver.cxx
        NetworkReceiver.h
        NetworkSender.h
        ReceiveQueue.cxx
        ReceiveQueue.h
        Singleton.h TestSender.cxx TestSender.h State.h TestReceiver.cxx TestReceiver.h)
