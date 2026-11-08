LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE    := antipause
LOCAL_SRC_FILES := main.cpp
LOCAL_LDLIBS    := -llog -ldl
include $(BUILD_SHARED_LIBRARY)
