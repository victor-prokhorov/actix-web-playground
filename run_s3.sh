alias grg="docker exec -ti garaged /garage" # make sure to match the container name

sudo docker run \
  -d \
  --name garaged \
  --restart always \
  --network host \
  -v ./garage.toml:/etc/garage.toml \
  -v /var/lib/garage/meta:/var/lib/garage/meta \
  -v /var/lib/garage/data:/var/lib/garage/data \
  garage:latest && \
    sudo docker logs -f garaged
