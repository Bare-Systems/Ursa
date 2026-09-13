# frozen_string_literal: true

class UrsaMajorHomelabSuite < Blink::Testing::Suite
  suite_name "Ursa Major Homelab"

  C2_BASE = "https://192.168.86.53:6708" unless const_defined?(:C2_BASE)

  test "c2 health endpoint returns healthy json",
       tags: [:smoke, :health],
       desc: "Verifies the published C2 listener responds over TLS on the homelab LAN IP." do
    res = http.get("#{UrsaMajorHomelabSuite::C2_BASE}/health")
    assert_status res, 200
    assert_body res, /healthy/
  end

  test "c2 container is running",
       tags: [:health],
       desc: "Checks that the C2 compose service is up and not restarting." do
    out = ssh_run("docker inspect --format '{{.State.Status}}' ursa-major-c2 2>/dev/null")
    assert_equal "running", out
  end

  test "c2 port is published on the lan address",
       tags: [:health],
       desc: "Confirms Docker published the TLS listener on 192.168.86.53:6708." do
    out = ssh_run("docker ps --filter name=^/ursa-major-c2$ --format '{{.Ports}}'")
    assert out.match?(/192\.168\.86\.53:6708->6708\/tcp/), "Unexpected C2 ports: #{out.inspect}"
  end
end
