pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build') {
            steps {
                sh '''
                    cmake -S . -B build
                    cmake --build build
                '''
            }
        }

	stage('Daemon Test') {
	    steps {
		sh '''
		    python3 Jenkinstests/test_daemon.py -v
		'''
	    }
	}
	
		
	stage('Flood Test') {
	    steps {
		sh 'docker build -t ips-flood-test -f Jenkinstests/Flood/Dockerfile .'
		sh '''
		    docker run --rm --privileged --network host \
		        -v "$WORKSPACE":/workspace \
		        -e IPS_REPO_ROOT=/workspace \
		        ips-flood-test \
		        bash -c "cd /workspace/Jenkinstests/Flood && chmod +x *.sh *.py && ./01_setup_veth.sh && ./02_run_ips.sh && python3 03_flood_test.py --blocklist-csv /workspace/data/blocklist.csv && ./04_cleanup.sh"
		'''
	    }
	}


        stage('Archive') {
            steps {
                archiveArtifacts artifacts: 'build/fast_path/ips_loader, build/fast_path/ips_injector', fingerprint: true
            }
        }
    }
}
