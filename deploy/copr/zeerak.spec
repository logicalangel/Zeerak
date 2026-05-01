Name:           zeerak
Version:        0.2.5
Release:        1%{?dist}
Summary:        Lightweight web GUI firewall for nftables

License:        Apache-2.0
URL:            https://github.com/logicalangel/Zeerak
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.26
BuildRequires:  systemd-rpm-macros
Requires:       nftables
Requires(pre):  shadow-utils
%{?systemd_requires}

%description
Zeerak is a single-binary, server-rendered web GUI for managing
nftables. It includes a CLI, an MCP server for AI assistants, and an
auto-rollback safety bar on every change.

%prep
%autosetup -n Zeerak-%{version}

%build
export CGO_ENABLED=0
go build -trimpath -ldflags="-s -w -X main.Version=%{version}" \
    -o zeerak-server ./cmd/zeerak-server
go build -trimpath -ldflags="-s -w -X main.Version=%{version}" \
    -o zeerak        ./cmd/zeerak
go build -trimpath -ldflags="-s -w -X main.Version=%{version}" \
    -o zeerak-mcp    ./cmd/zeerak-mcp

%install
install -Dm755 zeerak-server  %{buildroot}%{_bindir}/zeerak-server
install -Dm755 zeerak         %{buildroot}%{_bindir}/zeerak
install -Dm755 zeerak-mcp     %{buildroot}%{_bindir}/zeerak-mcp
install -Dm644 deploy/systemd/zeerak-server.service \
    %{buildroot}%{_unitdir}/zeerak-server.service
install -Dm640 deploy/examples/zeerak.yaml \
    %{buildroot}%{_sysconfdir}/zeerak/zeerak.yaml
install -Dm644 deploy/caddy/Caddyfile.example \
    %{buildroot}%{_docdir}/%{name}/Caddyfile.example
install -Dm644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -Dm644 NOTICE  %{buildroot}%{_docdir}/%{name}/NOTICE

%pre
getent group zeerak >/dev/null || groupadd -r zeerak
getent passwd zeerak >/dev/null || \
    useradd -r -g zeerak -d /var/lib/zeerak -s /sbin/nologin \
            -c "Zeerak nftables panel" zeerak

%post
%systemd_post zeerak-server.service

%preun
%systemd_preun zeerak-server.service

%postun
%systemd_postun_with_restart zeerak-server.service

%files
%{_bindir}/zeerak-server
%{_bindir}/zeerak
%{_bindir}/zeerak-mcp
%{_unitdir}/zeerak-server.service
%dir %{_sysconfdir}/zeerak
%config(noreplace) %{_sysconfdir}/zeerak/zeerak.yaml
%doc %{_docdir}/%{name}/Caddyfile.example
%license %{_docdir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/NOTICE

%changelog
* Fri May 01 2026 logicalangel <noreply@github.com> - 0.2.5-1
- v0.2.5: web panel, preset wizard, MCP v0, CLI, packaging.
