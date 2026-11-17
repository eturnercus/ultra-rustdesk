Name:       ultrarustdesk
Version:    1.5.1
Release:    0
Summary:    RPM package
License:    GPL-3.0
URL:        https://github.com/eturnercus/ultra-rustdesk
Vendor:     eturnercus
Requires:   gtk3 libxcb1 libXfixes3 alsa-utils libXtst6 libva2 gstreamer-plugins-base gstreamer-plugin-pipewire
Recommends: libayatana-appindicator3-1 xdotool
Provides:   libdesktop_drop_plugin.so()(64bit), libdesktop_multi_window_plugin.so()(64bit), libfile_selector_linux_plugin.so()(64bit), libflutter_custom_cursor_plugin.so()(64bit), libflutter_linux_gtk.so()(64bit), libscreen_retriever_plugin.so()(64bit), libtray_manager_plugin.so()(64bit), liburl_launcher_linux_plugin.so()(64bit), libwindow_manager_plugin.so()(64bit), libwindow_size_plugin.so()(64bit), libtexture_rgba_renderer_plugin.so()(64bit)

# https://docs.fedoraproject.org/en-US/packaging-guidelines/Scriptlets/

%description
Ultra RustDesk - low-latency remote desktop, a fork of RustDesk.

%prep
# we have no source, so nothing here

%build
# we have no source, so nothing here

# %global __python %{__python3}

%install

mkdir -p "%{buildroot}/usr/share/ultrarustdesk" && cp -r ${HBB}/flutter/build/linux/x64/release/bundle/* -t "%{buildroot}/usr/share/ultrarustdesk"
mkdir -p "%{buildroot}/usr/bin"
install -Dm 644 $HBB/res/ultrarustdesk.service -t "%{buildroot}/usr/share/ultrarustdesk/files"
install -Dm 644 $HBB/res/ultrarustdesk.desktop -t "%{buildroot}/usr/share/ultrarustdesk/files"
install -Dm 644 $HBB/res/ultrarustdesk-link.desktop -t "%{buildroot}/usr/share/ultrarustdesk/files"
install -Dm 644 $HBB/res/128x128@2x.png "%{buildroot}/usr/share/icons/hicolor/256x256/apps/ultrarustdesk.png"
install -Dm 644 $HBB/res/scalable.svg "%{buildroot}/usr/share/icons/hicolor/scalable/apps/ultrarustdesk.svg"

%files
/usr/share/ultrarustdesk/*
/usr/share/ultrarustdesk/files/ultrarustdesk.service
/usr/share/icons/hicolor/256x256/apps/ultrarustdesk.png
/usr/share/icons/hicolor/scalable/apps/ultrarustdesk.svg
/usr/share/ultrarustdesk/files/ultrarustdesk.desktop
/usr/share/ultrarustdesk/files/ultrarustdesk-link.desktop

%changelog
# let's skip this for now

%pre
# can do something for centos7
case "$1" in
  1)
    # for install
  ;;
  2)
    # for upgrade
    systemctl stop ultrarustdesk || true
  ;;
esac

%post
cp /usr/share/ultrarustdesk/files/ultrarustdesk.service /etc/systemd/system/ultrarustdesk.service
cp /usr/share/ultrarustdesk/files/ultrarustdesk.desktop /usr/share/applications/
cp /usr/share/ultrarustdesk/files/ultrarustdesk-link.desktop /usr/share/applications/
ln -sf /usr/share/ultrarustdesk/ultrarustdesk /usr/bin/ultrarustdesk
systemctl daemon-reload
systemctl enable ultrarustdesk
systemctl start ultrarustdesk
update-desktop-database
gtk-update-icon-cache -f -t -q /usr/share/icons/hicolor >/dev/null 2>&1 || true

%preun
case "$1" in
  0)
    # for uninstall
    systemctl stop ultrarustdesk || true
    systemctl disable ultrarustdesk || true
    rm /etc/systemd/system/ultrarustdesk.service || true
  ;;
  1)
    # for upgrade
  ;;
esac

%postun
case "$1" in
  0)
    # for uninstall
    rm /usr/bin/ultrarustdesk || true
    rmdir /usr/lib/ultrarustdesk || true
    rmdir /usr/local/ultrarustdesk || true
    rmdir /usr/share/ultrarustdesk || true
    rm /usr/share/applications/ultrarustdesk.desktop || true
    rm /usr/share/applications/ultrarustdesk-link.desktop || true
    update-desktop-database
  ;;
  1)
    # for upgrade
    rmdir /usr/lib/ultrarustdesk || true
    rmdir /usr/local/ultrarustdesk || true
  ;;
esac
