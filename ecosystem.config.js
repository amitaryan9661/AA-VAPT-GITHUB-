module.exports = {
  apps: [
    {
      name: "aa-vapt",
      script: "/home/amit_aryan/aa-vapt/.venv/bin/python3",
      args: "-m uvicorn backend.main:app --host 0.0.0.0 --port 8000",
      interpreter: "none",
      cwd: "/home/amit_aryan/aa-vapt",
      autorestart: true,
      watch: false,
      max_memory_restart: "2G",
      env: {
        PYTHONUNBUFFERED: "1",
        VIRTUAL_ENV: "/home/amit_aryan/aa-vapt/.venv",
        PATH: "/home/amit_aryan/aa-vapt/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
      },
      error_file: "/home/amit_aryan/aa-vapt/logs/error.log",
      out_file: "/home/amit_aryan/aa-vapt/logs/out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss"
    }
  ]
}
