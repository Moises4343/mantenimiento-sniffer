import React, { useState, useEffect } from 'react';
import { CSVLink } from 'react-csv';
import Swal from 'sweetalert2';
import Buscar from './search';

const Table = () => {

	const [csvData, setCsvData] = useState([]);

	const [sniffData, setSniffData] = useState([]);

	const [searchValue, setSearchValue] = useState("");

	const [time, setTime] = useState(new Date().toLocaleTimeString());



	const today = new Date();
	const year = today.getFullYear();
	const month = (today.getMonth() + 1).toString().padStart(2, '0');
	const day = today.getDate().toString().padStart(2, '0');

	


	const formattedDate = `${year}-${month}-${day}`;
	useEffect(() => {
		const interval = setInterval(() => {
			setTime(new Date().toLocaleTimeString());
		}, 1000);

		return () => clearInterval(interval);
	}, []);
	const startSniffer = () => {
		Swal.fire({
			title: 'Escaneando red...',
			html: 'Este proceso puede tardar unos momentos.',
			allowOutsideClick: false,
			didOpen: async () => {
				Swal.showLoading();
				await fetch('http://localhost:5000/sniff', { method: 'POST' });
				Swal.close();
				window.location.reload();

			}
		});

	};

	useEffect(() => {
		fetch('http://localhost:5000/sniff')
			.then(response => response.json())
			.then(data => {
				setSniffData(data);
				setCsvData(data);
			})
			.catch(error => console.log(error));
	}, []);

	const handleSearchChange = (e) => {
		setSearchValue(e.target.value);
	};
	const fetchSniffData = async () => {
		let url;
		if (searchValue.match(/^\d{4}-\d{2}-\d{2}$/)) {
			url = `http://localhost:5000/sniff/${searchValue}`;
		} else if (searchValue.match(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/)) {
			url = `http://localhost:5000/sniff/mac/${searchValue}`;
		} else {
			return;
		}

		const response = await fetch(url);
		const data = await response.json();
		setSniffData(data);
		setCsvData(data);
	};


	return (

		<>
			<Buscar
				handleSearchChange={handleSearchChange}
				searchValue={searchValue}
				fetchSniffData={fetchSniffData}
			/>
			<main>
				<div className="head-title">
					<div className="left">
						<h1>Sniffer</h1>

					</div>
					<a onClick={startSniffer} href="#" className="btn-download">
						<span className="text">Escanear red</span>
					</a>
					<a href="#" className="btn-download">
						<i className='bx bxs-cloud-download' ></i>
						<CSVLink data={csvData} filename={'sniff-data.csv'} className="link">
							<span className="link-text">Download </span>

						</CSVLink>
					</a>

				</div>

				<ul className="box-info">
					<li>
						<i className='bx -check' >
							<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" fill="currentColor" class="bi bi-alarm" viewBox="0 0 16 16">
								<path d="M8.5 5.5a.5.5 0 0 0-1 0v3.362l-1.429 2.38a.5.5 0 1 0 .858.515l1.5-2.5A.5.5 0 0 0 8.5 9V5.5z" />
								<path d="M6.5 0a.5.5 0 0 0 0 1H7v1.07a7.001 7.001 0 0 0-3.273 12.474l-.602.602a.5.5 0 0 0 .707.708l.746-.746A6.97 6.97 0 0 0 8 16a6.97 6.97 0 0 0 3.422-.892l.746.746a.5.5 0 0 0 .707-.708l-.601-.602A7.001 7.001 0 0 0 9 2.07V1h.5a.5.5 0 0 0 0-1h-3zm1.038 3.018a6.093 6.093 0 0 1 .924 0 6 6 0 1 1-.924 0zM0 3.5c0 .753.333 1.429.86 1.887A8.035 8.035 0 0 1 4.387 1.86 2.5 2.5 0 0 0 0 3.5zM13.5 1c-.753 0-1.429.333-1.887.86a8.035 8.035 0 0 1 3.527 3.527A2.5 2.5 0 0 0 13.5 1z" />
							</svg></i>
						<span className="text">
							<h3>Hora</h3>
							<p>{time}</p>
						</span>
					</li>

					<li>
						<i className='bx ' >
							<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" fill="currentColor" class="bi bi-calendar2-week" viewBox="0 0 16 16">
								<path d="M3.5 0a.5.5 0 0 1 .5.5V1h8V.5a.5.5 0 0 1 1 0V1h1a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V3a2 2 0 0 1 2-2h1V.5a.5.5 0 0 1 .5-.5zM2 2a1 1 0 0 0-1 1v11a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V3a1 1 0 0 0-1-1H2z" />
								<path d="M2.5 4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5H3a.5.5 0 0 1-.5-.5V4zM11 7.5a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-1a.5.5 0 0 1-.5-.5v-1zm-3 0a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-1a.5.5 0 0 1-.5-.5v-1zm-5 3a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-1a.5.5 0 0 1-.5-.5v-1zm3 0a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-1a.5.5 0 0 1-.5-.5v-1z" />
							</svg></i>

						<span className="text">
							<h3>Fecha </h3>
							<p>{formattedDate}</p>
						</span>
					</li>
				</ul>


				<div className="table-data">
					<div className="order">
						<div className="head">
							<h3>Datos</h3>

						</div>
						<div style={{ height: '400px', overflow: 'scroll' }}>
							<table id="my-table">
								<thead>
									<tr>
										<th>mac_src</th>
										<th>ip_src</th>
										<th>tam_src</th>
										<th>fecha</th>
										<th>hora</th>
										<th>Sistema operativo</th>
										<th>Protocolo</th>
									</tr>
								</thead>
								<tbody>
									{sniffData.map((data) => (
										<tr key={data.id}>
											<td>{data.mac_src}</td>
											<td>{data.ip_src}</td>
											<td>{data.tam_src}</td>
											<td>{data.fecha}</td>
											<td>{data.hora}</td>
											<td>{data.os}</td>
											<td>{data.protocol}</td>
										</tr>
									))}
								</tbody>
							</table>

						</div>
					</div>


					

				</div>
			</main>
		</>
	)
}
export default Table;